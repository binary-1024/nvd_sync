# NVD mirror (GitHub Actions) — 设置说明

把这套文件放进一个**新的公开 GitHub 仓库**,让 GitHub Actions 每小时增量抓 NVD
CVE + cpematch,按"一记录一文件 + 前缀分片"提交。你本地用 `cve-git-sync` /
`cpematch-git-sync` 拉增量导入(见主项目 `data-infra`)。

## 文件

```
nvd_mirror.py                  # 独立抓取脚本(stdlib only)
.github/workflows/sync.yml     # 每小时定时 + 提交变更
cve/<shard>/<CVE-ID>.json      # 产物:每条 CVE 一个文件
cpematch/<shard>/<ID>.json     # 产物:每条 matchString 一个文件
```
`<shard>` = sha1(id) 前 2 位十六进制(256 个均匀分桶,避免单目录几十万文件)。

## 一、建仓 + 放文件

```bash
# 新建一个公开仓库后:
git clone https://github.com/<you>/nvd-mirror && cd nvd-mirror
cp -r <data-infra>/deploy/nvd-mirror/{nvd_mirror.py,.github} .
git add -A && git commit -m "init" && git push
```

## 二、加 NVD 密钥(Actions secret)

仓库 Settings → Secrets and variables → Actions → New repository secret:
- Name: `NVD_API_KEYS`
- Value: 你的 NVD key,逗号或空格分隔(多 key 会轮换)。

> 公开仓库的 Actions 分钟数无限;NVD 数据本身公开,放公开仓合适。

## 三、首次种子(全量,一次性)

种子会写约 36 万 CVE + 64 万 cpematch 文件(大提交)。两种做法:
- **本地种子再推**(推荐,避免 Action 超时):
  ```bash
  NVD_API_KEYS="k1,k2,..." python nvd_mirror.py --base . --seed
  git add -A && git commit -m "seed" && git push
  ```
- 或在 Actions 页面 `Run workflow` 勾选 `seed`(注意单次 job ≤ ~5.5h)。

## 四、之后

`sync.yml` 每小时(:00 UTC)跑增量。**窗口锚在上次成功抓取的时刻**(每种数据各一个
锚点,存 `state/last_window_end.json`,随产物一起提交),再往前留 `--overlap-min`
(默认 60 分钟)重叠;首次没有锚点时退回"过去 `--window-min`(默认 120)分钟"。
跨度超过 NVD API 的 120 天上限时自动切段顺序抓。

★为什么锚定(2026-09-03,第 0 层审计 F-01):此前窗口固定为"现在往前 120 分钟",
而 GitHub 定时工作流是尽力而为 —— 两次触发间隔 >2h,中间 NVD 修改的记录就永久落在
窗外(60 天 79 个缺口 / 91 小时,NVD API 对账 ≈195 CVE 陈旧、≥1,022 判据永久缺失,
本地 `--full` 只重导镜像补不回)。锚定后:一次没跑、跑失败,下一次都从旧锚点重放。

失败语义:任一端点失败脚本非零退出 → 工作流不提交 → 该端点锚点不动;成功的端点
已推进锚点(状态文件写在每个端点成功之后)。

**回补**:Actions 页面 `Run workflow`,填 `since`(如 `2026-06-28T00:00:00Z`,
镜像诞生日),脚本按 119 天一段抓完 since..now 并把两个锚点推到 now。

`state/` 不在 `cve/`、`cpematch/` 前缀下,本地 `nvd-git-sync` 会忽略它。

## 五、本地消费(在 data-infra 项目里)

本仓一个 repo 同时装 `cve/` 和 `cpematch/`,所以用**组合命令 `nvd-git-sync`**——
一次 clone/pull、把变更文件分别导入 CVE 与 cpematch(避免重复克隆,也避免两条命令
分别 pull 导致漏导):

```bash
python -m osvdb.cli nvd-git-sync --repo https://github.com/<you>/nvd-mirror
python -m osvdb.cli wh-build
```
首次 clone 全量、之后 `git pull` 只导变更(增量、断点/重试/自愈,见主项目 osv_git)。

> `cve-git-sync` / `cpematch-git-sync` 仅用于"cve 和 cpematch 各自独立 repo"的场景;
> 用本套(单仓双目录)请用 `nvd-git-sync`。

## 维护

- 历史会随每小时提交增长;定期 `git gc --aggressive` 或在 Actions 里周期性运行,
  必要时重建仓库(数据可从 NVD 重新种子)。
- 想调频率/窗口:改 `sync.yml` 的 cron 与 `--window-min`(窗口要 > 间隔)。
