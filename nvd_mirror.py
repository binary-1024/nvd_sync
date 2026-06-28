#!/usr/bin/env python3
"""Standalone NVD -> git mirror writer (for a GitHub Actions cron job).

Fetches NVD CVE and CPE-Match data and writes one sharded JSON file per record:
    cve/<shard>/<CVE-ID>.json            (the bare NVD `cve` dict)
    cpematch/<shard>/<matchCriteriaId>.json   (the bare `matchString` dict)
where <shard> = first 2 hex of sha1(id), giving 256 even buckets.

Modes:
  default  : incremental — only records modified in the last --window-min minutes
             (uses NVD lastModStartDate/lastModEndDate). Small per-hour diffs.
  --seed   : full dump (one-time; large). Run once locally or via workflow_dispatch.

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
                  window_min=None, per_page=2000, concurrency=4) -> int:
    """Fetch (incremental window or full) and write sharded files. Returns count."""
    base_params = {"resultsPerPage": per_page}
    if window_min:
        end = datetime.now(timezone.utc).replace(microsecond=0)
        start = end - timedelta(minutes=window_min)
        # NVD wants extended ISO-8601 with millis + colon offset (e.g. ...000+00:00)
        base_params["lastModStartDate"] = start.isoformat(timespec="milliseconds")
        base_params["lastModEndDate"] = end.isoformat(timespec="milliseconds")

    first = fetch_page(url, {**base_params, "startIndex": 0}, pool)
    total = int(first.get("totalResults", 0))
    written = 0

    def handle(page: dict):
        n = 0
        for it in page.get(results_key, []) or []:
            rec = it.get(item_key, it)
            rid = rec.get("id") or rec.get("matchCriteriaId")
            if rid:
                write_record(base, kind, rid, rec)
                n += 1
        return n

    written += handle(first)
    log(f"{kind}: {total} modified record(s) to mirror")
    starts = list(range(per_page, total, per_page))
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futs = {ex.submit(fetch_page, url, {**base_params, "startIndex": s}, pool): s
                for s in starts}
        for fut in as_completed(futs):
            written += handle(fut.result())
    log(f"{kind}: wrote {written} file(s)")
    return written


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default=".", help="repo root to write into")
    ap.add_argument("--seed", action="store_true", help="full dump (one-time)")
    ap.add_argument("--window-min", type=int, default=120,
                    help="incremental lookback minutes (ignored with --seed)")
    ap.add_argument("--only", choices=["cve", "cpematch"], default=None)
    args = ap.parse_args(argv)

    keys = load_keys()
    log(f"{'seed' if args.seed else f'incremental window={args.window_min}m'}; "
        f"{len(keys)} API key(s)")
    pool = KeyPool(keys)
    window = None if args.seed else args.window_min

    total = 0
    if args.only in (None, "cve"):
        total += sync_endpoint(CVE_URL, "vulnerabilities", "cve", "cve",
                               args.base, pool, window_min=window, per_page=2000)
    if args.only in (None, "cpematch"):
        total += sync_endpoint(CPEMATCH_URL, "matchStrings", "matchString",
                               "cpematch", args.base, pool, window_min=window,
                               per_page=500)
    log(f"done: {total} record file(s) written/updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
