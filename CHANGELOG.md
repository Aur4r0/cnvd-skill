# 更新日志

## [2.5] - 2026-11-16

### 修复

- **扫描异常不再静默吞掉**：`ex.map()` 返回值未被迭代，`work()` 内异常完全丢失——目标不进 findings、不进台账、进度照走，整轮看似全部完成实则有目标被跳过。现拆分 `work`/`scan_target`，异常在 `work` 内收敛；失败目标台账记 `ERROR` 且**不算已完成**，`--resume` 会自动重试；结尾打印失败汇总
- **`exclude_any` 数字状态码误杀真命中**：原为纯子串匹配，响应体含 `SN4012233` 这类数字串的真命中会被 `401` 排除词丢弃（21 条规则中 15 条受影响）。现纯 3 位数字只在状态层面生效，不参与 body 匹配；`login`/`unauthorized` 等字符串排除不变
- **统一 RTSP 判据**：`verify_rtsp2.py` 的 `has_sdp()` 原有 `m=video`+`a=control` 宽松分支，会 confirm 主扫描不认的命中。现与 `cnvd_check.py` 一致，严格要求 `v=0` + `m=video/audio`
- **RTSP 响应按 Content-Length 收满**：原读到首个 `CRLFCRLF` 且 >200 字节即停，跨段 SDP 会漏读 `v=0`/`m=video`，造成假阴性
- **targets.csv 脏数据**：空 IP / 非法端口 / 越界端口现在被拦截并报告行号，不再拿 `:80` 这类目标发请求；`r["ip"]` 为 `None` 时的 `AttributeError` 亦已消除。形如 IPv4 的越界地址（`192.168.1.256`）拒绝而非降级为主机名
- **`utcfromtimestamp` 弃用**：`verify_newfe_A.py` 改用 `datetime.fromtimestamp(t, timezone.utc)`，Python 3.12+ 不再告警

### 文档

- 新增 [docs/修复说明-2.5.md](docs/修复说明-2.5.md)：五条修复的现象 / 根因 / 改法 / 验证数据

### 未改动

- 端点字典规则内容与判据语义
- SKILL.md 方法论、合规红线与厂商资质门槛
- `cnvd_recon.py` 的通道逻辑

## [2.4] - 2026-11-16

### 修复

- **新增入库 `api_keys.example.json`**（原 `api_keys.json` 因 `.gitignore` 不入库，新克隆缺文件）。`cnvd_recon.py` 找不到真实配置时回退读占位模板并打印明确提示（exit 2），不再抛 `FileNotFoundError` traceback；`校验.bat` 第 4a 步区分「文件缺失」与「还是占位符」
- **`--resume` 改为目标级断点**：新增 `<out>.scanned.csv` 台账，每扫完一个目标（含零命中）即落盘。原实现从 findings 推导已完成目标，零命中目标永远不在其中，续跑时会被全部重扫。无台账的旧 run 自动回退到原推导逻辑并打印提示。命中同时增量写入 findings，进程被杀不丢结果
- **RTSP/FTP 探针纳入 Pacer**：原实现绕过节流器直连，"单 IP 串行 + 间隔 ≥1s" 只对 HTTP 成立。现三类探针共用同一 IP 锁；RTSP 同连接内多条 DESCRIBE 也按 interval 节流（实测 6 条间隔均 ≥1.00s）
- **RTSP/FTP 探测目标实际端口**：原实现硬用规则的 `port` 字段（554/21），忽略 targets.csv 的行端口，非标准端口（如 8554）会被漏探。现优先探目标行端口，目标是常见 Web 端口时才退回规则端口；findings 新增 `probe_port` 列记录实际探测端口，`url` 亦按实际端口生成
- `cnvd_check.py` 双差分复现请求前的双重等待（`time.sleep` + `pacer.acquire`）合并为一次；Pacer 改为在 release 时记录时间戳，间隔从上次请求结束算起

### 文档

- 新增 [docs/修复说明-2.4.md](docs/修复说明-2.4.md)：四条修复的现象 / 根因 / 改法 / 验证结果，含已知遗留项
- README / 移植说明 / 使用教程：FOFA 配置改为「复制 example 再填」
- FAQ：断点续跑说明改为台账机制

### 未改动

- 端点字典（`tools/rules/*.json`）的规则内容与判据
- SKILL.md 的方法论、合规红线与厂商资质门槛
- 抽验脚本（`verify_*.py`）的判据逻辑

## [2.3] - 2026-09-13

CNVD 通用型未授权漏洞广扫 skill 便携包。

### 核心特性

- **无产出不停**（停机语义）：唯一合法停机 = 已挖到「可提交级」洞并落盘（命中 ≥10 台 + 查重 no_duplicate + 独立复验 confirmed + 厂商资质达标 + 报告落盘）。换线 ≠ 收工，报告落盘 ≠ 终点；诚实条款禁止包装 mock 项谎报出货
- **厂商资质门槛**（CNVD 发证硬门槛）：① 通用型漏洞 ② 厂商注册资本实缴 > 5000 万元人民币 ③ 优先国内厂商。甜点区 = 注册资本过线但知名度低的中型/小厂（SKILL.md §1.1a）
- **复现规范**（反虚构铁律）：复现步骤优先 curl / 浏览器直接访问；curl 无法表达时贴真实数据包；禁止任何虚构——所有请求/响应必须是实操原文，所有复现方式必须亲自跑过（SKILL.md §1.4a）

### 组件

- `skills/cnvd/SKILL.md` — skill 本体（流程/原则/判据/合规红线）
- `tools/scripts/` — 9 个 Python 脚本（纯标准库，零 pip 依赖）
- `tools/rules/` — 8 文件 28 条端点字典（核心资产）
- `示例产出/` — 脱敏格式样例
- `校验.bat` — 环境自检 + 冒烟测试
- `api_keys.json` — FOFA 多通道配置模板

### 修复（发布于 2026-09-13）

- `cnvd_check.py` 补 `import os`（`--resume` 断点续跑曾必崩）
- `.gitignore` 修正：`cnvd/` 规则不再误伤 `skills/cnvd/`；示例产出两个脱敏样例 CSV 保留入库
- 抽验脚本默认路径从 `__file__` 绝对路径改为相对路径（对齐「输出落在当前工作目录」）

---

*本项目遵循语义化版本。当前版本：2.5*
