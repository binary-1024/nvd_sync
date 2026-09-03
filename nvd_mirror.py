#!/usr/bin/env python3
"""Standalone NVD -> git mirror writer (for a GitHub Actions cron job).

Fetches NVD CVE and CPE-Match data and writes one sharded JSON file per record:
    cve/<shard>/<CVE-ID>.json            (the bare NVD `cve` dict)
    cpematch/<shard>/<matchCriteriaId>.json   (the bare `matchString` dict)
where <shard> = first 2 hex of sha1(id), giving 256 even buckets.

Modes:
  default  : incremental — records modified since the **last successful run**
             (anchor kept per kind in state/last_window_end.json), minus
             --overlap-min of overlap. No anchor yet -> fall back to the last
             --window-min minutes. Spans longer than the NVD API limit (120 days)
             are fetched in consecutive chunks.
  --since  : explicit backfill start (ISO-8601 UTC); anchors advance to now on success.
  --seed   : full dump (one-time; large). Run once locally or via workflow_dispatch.

★Why anchor (2026-09-03, layer-0 audit F-01): a fixed "now - 120 min" window silently
loses every record NVD modified between two Actions runs more than 2 h apart — and
GitHub's cron is best-effort (79 gaps / 91 h in 60 days; ~195 CVE stale, >=1,022
cpematch permanently missing). A failed kind keeps its old anchor, so the next run
replays the same span instead of dropping it.

No external deps (stdlib only). Reads NVD keys from env NVD_API_KEYS
(comma/space separated) or NVD_API_KEY; rotates across them with cooldown.

The companion GitHub Actions workflow commits whatever files changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPEMATCH_URL = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
UA = {"User-Agent": "nvd-mirror/1.0"}


def log(msg: str) -> None:
    sys.stderr.write(f"[{datetime.now(timezone.utc).isoformat()}] {msg}\n")
    sys.stderr.flush()


def load_keys() -> list[str]:
    keys: list[str] = []
    multi = os.environ.get("NVD_API_KEYS", "")
    if multi:
        keys += [k.strip() for k in multi.replace(",", " ").split() if k.strip()]
    one = os.environ.get("NVD_API_KEY")
    if one:
        keys.append(one.strip())
    seen, out = set(), []
    for k in keys:
        if k and k not in seen:
            seen.add(k); out.append(k)
    return out


class KeyPool:
    def __init__(self, keys, interval=0.62):
        self.keys = list(keys); self.iv = interval
        self.last = {k: 0.0 for k in self.keys}
        self.cool = {k: 0.0 for k in self.keys}
        self.lock = threading.Lock()

    def acquire(self):
        if not self.keys:
            return None
        while True:
            with self.lock:
                now = time.time()
                ready = [k for k in self.keys if self.cool[k] <= now]
                if ready:
                    k = min(ready, key=lambda x: self.last[x])
                    w = self.iv - (now - self.last[k])
                    if w <= 0:
                        self.last[k] = now; return k
                    nap = w
                else:
                    nap = min(self.cool.values()) - now + 0.01
            time.sleep(max(nap, 0.0))

    def penalize(self, k, secs):
        with self.lock:
            if k in self.cool:
                self.cool[k] = time.time() + min(max(secs, 0), 3600)


def shard(id_: str) -> str:
    return hashlib.sha1(id_.encode()).hexdigest()[:2]


def write_record(base: str, kind: str, id_: str, obj: dict) -> None:
    d = os.path.join(base, kind, shard(id_))
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, id_.replace("/", "_") + ".json.tmp")
    final = os.path.join(d, id_.replace("/", "_") + ".json")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, final)


STATE_REL = os.path.join("state", "last_window_end.json")
NVD_MAX_SPAN_DAYS = 119          # NVD API: lastModStartDate..EndDate must be <= 120 days


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _parse_ts(s: str) -> datetime:
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def load_state(base: str) -> dict:
    path = os.path.join(base, STATE_REL)
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_state(base: str, state: dict) -> None:
    path = os.path.join(base, STATE_REL)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def plan_windows(kind: str, state: dict, now: datetime, *, window_min: int = 120,
                 overlap_min: int = 60, since: datetime | None = None,
                 max_span_days: int = NVD_MAX_SPAN_DAYS) -> list[tuple[datetime, datetime]]:
    """[(start, end), ...] covering the span to fetch; the last end is *now*.

    start = --since if given; else anchor(kind) - overlap; else now - window_min.
    An anchor in the future (clock skew / dirty state) degrades to the fallback
    rather than producing an empty or inverted window.
    """
    if since is not None:
        start = since
    elif kind in state:
        start = _parse_ts(state[kind]) - timedelta(minutes=overlap_min)
    else:
        start = now - timedelta(minutes=window_min)
    if start >= now:
        start = now - timedelta(minutes=window_min)
    step = timedelta(days=max_span_days)
    out: list[tuple[datetime, datetime]] = []
    a = start
    while now - a > step:
        out.append((a, a + step)); a += step
    out.append((a, now))
    return out


def fetch_page(url, params, pool, *, retries=6, retry_wait=5.0, timeout=90) -> dict:
    """One page with key rotation + bounded retry.

    Rate-limit (403/429/503) -> rotate/cool down and keep trying (expected
    backpressure). Transient server/network errors (500/502/504/URLError/timeout)
    -> bounded retry; after *retries* give up so a scheduled job fails fast and
    the next run catches up (windows overlap).
    """
    attempt = 0
    while True:
        key = pool.acquire()
        headers = dict(UA)
        if key:
            headers["apiKey"] = key
        try:
            req = urllib.request.Request(f"{url}?{urllib.parse.urlencode(params)}",
                                         headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):
                pool.penalize(key, float(e.headers.get("Retry-After") or 30))
                if not pool.keys:
                    time.sleep(30)
                continue
            if e.code in (500, 502, 504):       # transient server error -> retry
                attempt += 1
                if attempt > retries:
                    raise
                time.sleep(min(retry_wait * attempt, 60))
                continue
            raise                                # 404 etc. -> real error
        except (urllib.error.URLError, TimeoutError, OSError):
            attempt += 1
            if attempt > retries:
                raise
            time.sleep(min(retry_wait * attempt, 60))


def sync_endpoint(url, results_key, item_key, kind, base, pool, *,
                  windows=None, per_page=2000, concurrency=4) -> int:
    """Fetch (seed when windows is None, else each lastMod window) and write files."""
    def handle(page: dict):
        n = 0
        for it in page.get(results_key, []) or []:
            rec = it.get(item_key, it)
            rid = rec.get("id") or rec.get("matchCriteriaId")
            if rid:
                write_record(base, kind, rid, rec)
                n += 1
        return n

    def one(base_params: dict, label: str) -> int:
        first = fetch_page(url, {**base_params, "startIndex": 0}, pool)
        total = int(first.get("totalResults", 0))
        written = handle(first)
        log(f"{kind} {label}: {total} record(s) to mirror")
        starts = list(range(per_page, total, per_page))
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
            futs = {ex.submit(fetch_page, url, {**base_params, "startIndex": s}, pool): s
                    for s in starts}
            for fut in as_completed(futs):
                written += handle(fut.result())
        return written

    written = 0
    if windows is None:
        written += one({"resultsPerPage": per_page}, "seed")
    else:
        for start, end in windows:
            # NVD wants extended ISO-8601 with millis + colon offset (...000+00:00)
            params = {"resultsPerPage": per_page,
                      "lastModStartDate": start.isoformat(timespec="milliseconds"),
                      "lastModEndDate": end.isoformat(timespec="milliseconds")}
            written += one(params, f"[{start.isoformat()} .. {end.isoformat()}]")
    log(f"{kind}: wrote {written} file(s)")
    return written


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default=".", help="repo root to write into")
    ap.add_argument("--seed", action="store_true", help="full dump (one-time)")
    ap.add_argument("--window-min", type=int, default=120,
                    help="fallback lookback minutes when a kind has no anchor yet")
    ap.add_argument("--overlap-min", type=int, default=60,
                    help="re-fetch this much before the anchor (eventual consistency)")
    ap.add_argument("--since", default=None,
                    help="backfill start, ISO-8601 UTC (e.g. 2026-06-28T00:00:00Z)")
    ap.add_argument("--only", choices=["cve", "cpematch"], default=None)
    args = ap.parse_args(argv)

    keys = load_keys()
    since = _parse_ts(args.since) if args.since else None
    now = _utcnow()
    state = {} if args.seed else load_state(args.base)
    mode = "seed" if args.seed else f"since={since.isoformat()}" if since else "incremental"
    log(f"{mode}; anchors={state}; {len(keys)} API key(s)")
    pool = KeyPool(keys)

    plan = [("cve", CVE_URL, "vulnerabilities", "cve", 2000),
            ("cpematch", CPEMATCH_URL, "matchStrings", "matchString", 500)]
    total = 0
    for kind, url, results_key, item_key, per_page in plan:
        if args.only not in (None, kind):
            continue
        windows = None if args.seed else plan_windows(
            kind, state, now, window_min=args.window_min,
            overlap_min=args.overlap_min, since=since)
        if windows:
            log(f"{kind}: {len(windows)} window(s) from {windows[0][0].isoformat()}")
        total += sync_endpoint(url, results_key, item_key, kind, args.base, pool,
                               windows=windows, per_page=per_page)
        # ★Only a kind that fully succeeded advances its anchor. An exception above
        #   propagates (non-zero exit -> the workflow commits nothing), so the next
        #   run replays the same span instead of losing it.
        state[kind] = now.isoformat()
        save_state(args.base, state)
    log(f"done: {total} record file(s) written/updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
