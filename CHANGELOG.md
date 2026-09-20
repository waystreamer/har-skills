# Changelog

本 fork 基于上游 [cyberspacesec/har-skills](https://github.com/cyberspacesec/har-skills) v0.1.1。

## [Unreleased] — fork: 面向第三方 App 抓包逆向的修复与增强

### 修复（上游 v0.1.1 的坑）

- **加载期强校验导致整个文件不可用**：Reqable/Charles/Fiddler 导出的 HAR 常带有
  `timings.send/wait/receive = -1`（HAR 规范允许）、缺失 `response.content.mimeType`、
  无名 cookie 等字段，上游在加载阶段就跑完整校验，任何一条 entry 不合规整个命令直接
  失败并吐出数百 KB 的错误列表，且没有放宽开关（`validate` 子命令的 `--strict` 只
  作用于 validate 自己）。本 fork 的 CLI 加载路径（`internal.LoadHar*`）改用新增的
  SDK 函数 `ParseHarSkipValidation` / `ParseHarFileAutoSkipValidation`，分析类命令
  不再因校验失败拒绝加载。需要严格合规的文件时用 `har sanitize` 显式产出。
- **`find`/`list` 的 INDEX 是结果集相对序号，不是全局 entry 号**：对过滤/排序后的
  结果，INDEX 列从 0 重编号，无法直接用于 `extract --index`，对倒序导出的 HAR
  定位具体请求非常绕。本 fork 引入 `entryIndex` 包装，`list`/`find`/`index` 输出的
  INDEX 一律是 `log.entries` 全局索引，可直接喂给 `extract --index` 和
  `diff-entry --index-a/--index-b`。
- **`extract` 只支持子串匹配**：新增 `--regex` 支持正则，与 `find --regex` 对齐。

### 新增命令

- **`diff-entry`**：字段级对比两个请求条目（同文件按全局索引，或跨文件按 URL）。
  逐项对比 query 参数、请求头、Cookie、POST 参数、响应头、Set-Cookie、响应体，
  按分组输出，单侧缺失标 `<absent>`。解决逆向分析最常见的"同一接口两次调用
  （一成一败）逐项对参数"需求——上游 `diff` 是文件级粗粒度，给不出这个。
- **`cookie-trace <name>`**：Cookie 溯源。按时间顺序给出该 Cookie 的
  下发点（SET，含首次下发的全局索引）→ 携带点（SENT）→ 值变化点，
  `--show-value=false` 可脱敏只看位置和值长度。
- **`sanitize <input> -o <output>`**：清洗第三方导出的 HAR 使其通过严格校验。
  直接操作 JSON（绕过解析器，文件再坏也能洗），就地修正 timings/时间/mimeType/
  无名 cookie/header/query，丢弃响应残缺的条目并计数。替代原先外挂的
  `har_sanitize.py` 脚本。

### 易用性

- `list`/`find`/`cookie-trace` 新增 `--url-max N`：URL 显示截断（按 rune 计，
  中文安全）。App 抓包 URL 动辄上千字符，默认输出在终端完全不可读。

### 结构

- 根目录 40+ 个 SDK 源文件移入 `pkg/har/`，测试数据移入 `pkg/har/testdata/`，
  根目录只留 CLI 入口、文档和工程文件。模块路径改为
  `github.com/waystreamer/har-skills`（`go install github.com/waystreamer/har-skills/cmd/har@latest`）。

### 文档

- `CLAUDE.md` 新增"侦察用 CLI、取证用 Python"分层定位：哪些分析 CLI 一条命令
  能出（info/find/extract/export/redact/diff-entry/cookie-trace），哪些必须写
  Python（链式 Referer 分析、自定义聚合、长 URL 二次加工）。
- 明确 `-o /tmp/x` 在 Windows 原生程序下会落到 `%LOCALAPPDATA%\Temp` 的坑。
