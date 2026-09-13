---
name: cnvd
description: CNVD 通用型未授权漏洞广扫 —— 冷门产品线 × 预置端点字典 × 批量验证，命中≥10 即一个洞，一晚滚 2-3 条线。说"cnvd"或"挖cnvd"触发。
license: MIT
compatibility: Requires filesystem-based agent with bash, Python 3.8+, and internet access.
allowed-tools: Bash Read Write Edit Grep Glob Task WebFetch WebSearch
metadata:
  user-invocable: "true"
  version: "2.0"
---

# cnvd 未授权广扫（v2.0 · 2026-08-22 重写）

> 定位：**广扫出量** —— 规则预置（AutoCVE 的快）+ 端点迁移（Lexmark 的量）+ 冷门筛选（大厂全重复的教训）。
> 触发：说「cnvd / 挖cnvd」；退出：说「恢复 / 退出cnvd」。
> v1.0（深挖单厂商 3-5 天）已被实战推翻：单固件深挖 3 小时才两洞，成本全在测绘/厂商反查/抽验/截图仪式上，且大厂必撞重复。

## 0. 三原则（全部来自实战教训）

1. **只打中危+能力点**（产证铁律）：判据 = 未授权能拿到什么，不是页面能不能打开。状态页/欢迎页/版本号 = 低危不投入。
2. **冷门优先**：大厂 = 重复重灾区（Lexmark 三报告全被 CNVD-2021-45229/45228/75312 驳回）。§3 黑名单 + 查重前移，只挑「有存量但不被关注」的厂商。
3. **命中≥10 即走**：案例 10 个就是达标线，不放大、不铺量、不截图（用户自复现）。

## 1. 流程（一产品线一循环，一晚 2-3 线）

```
准备(10min) → 扫描(脚本) → 查重+抽验(1 agent) → 报告(主对话) → 下一线
```

### 1.1 准备
1. `python cnvd_recon.py --preset <类型>` 拉存量（preset：nvr/printer/industrial/network/access/nas/conference）
2. 指纹聚类（title/server 分组）→ **排除 §3 大厂黑名单** → 挑冷门线（存量 ≥300 的厂商指纹组）
3. 顺手 WebSearch 查「厂商名 CNVD 未授权」条目数——**条目 >2 的直接跳过**（查重前移，白干率大降）
4. 按产品线选 §2 端点字典 rules 文件；新线无字典 → 用 rules_generic.json 起步 + 抓 2-3 台设备页面挖接口（≤10 分钟）

### 1.2 扫描（脚本，主对话不亲手抓包）
1. 资产 CSV → targets.csv（表头 ip,port）
2. `python cnvd_check.py --targets targets.csv --rules rules_xxx.json --geo --out findings.csv`
   - 判据内建（v2 已修）：HTTP 双差分（无 cookie 两次可复现）+ match 字段验证；**RTSP 必须 DESCRIBE 200 且 SDP 含 v=0+m=video/audio**，OPTIONS-only 直接丢弃（08-22 返工教训）
3. findings 按 rule_id 聚类：**命中 ≥10 → 进查重；<10 → 换下一线**（不恋战）

### 1.3 查重+抽验（合并成 1 个 agent，一次派发两活）
- 输入：findings.csv 只给 `ip,port,rule_id,url` 四列 + 厂商名（不给 snippet 防预判）
- 输出：`dedup_report.json` + `verify_report.json`
- 检查项（一次性穷举）：
  - **查重四源**：CNVD 官网 / CNNVD / Seebug / WebSearch（site:cnvd.org.cn 厂商名+漏洞点），每条 same(same|similar|different) 判定 + 理由
  - **独立复验 3-5 台**（该洞命中里的随机台）：无 cookie 裸请求复现 / 真实数据非 mock / 蜜罐三判（ip-api 查 geo，云段=yes 优先怀疑）/ 设备自洽
  - 排除必带 fail_reason，禁止"没发现"式结论
- 裁决：`duplicate → 换点或换线`；`no_duplicate + 复验 confirmed → 进报告`
- 红线：只读 GET/OPTIONS/DESCRIBE；单 IP 间隔 ≥1s；不下载敏感文件

### 1.4 报告（主对话）
- 每洞两版：提交版 + 复现版，命名 `<目标>-<日期>-<等级>-<漏洞名>[-提交版|-复现版].md`（hark 命名格式），**产出报告统一放桌面：`Desktop\cnvd\<厂商>\<日期>\`**（即用户桌面下的 cnvd 文件夹，Windows 直接可用；Linux/macOS 对照本机桌面路径）
- 案例 IP 全量导 `全部案例IP.txt` 同目录（分层：批量命中 / 抽验确认 / confirmed）
- **定级交用户拍板**（CLAUDE.md 铁律），不擅自定义
- 报告写「与历史漏洞差异」段（型号/路径/参数差异点，应对未公开重复）
- 截图：默认不做，用户自己复现看

### 1.5 循环
一条线完成（报告落盘）→ 归档 → 下一条线。每晚目标 2-3 条线 / 3-5 洞。

## 2. 端点字典库（核心资产 · `<包根>/tools/rules/`）

> 端点来自实战验证，跨厂商迁移复用。新洞入库规则：实战确认后追加，标注来源+判据。

| 文件 | 产品线 | 端点 | 来源 |
|------|--------|------|------|
| rules_boa.json | NVR/HVR（Boa 固件） | Config.json(ZWP2P UID) / ONVIF / RTSP / FTP 匿名 | 中维 ZWP2P 实战（2026-08-22） |
| rules_newfe.json | 新前端 NVR/IPC | Config.json(UID) / 超级密码兑换码 / 找回接口 / RTSP / ONVIF | 08-24 新前端线（p6scloud 系） |
| rules_access_menjin.json | 门禁（门禁专家） | 固件指纹 / 登录页预填默认账密 | 08-24 门禁线 |
| rules_access_drid.json | 门禁（Dr.ID） | IIS 栈指纹 / o_*.aspx 未授权候选 | 08-24 门禁线 |
| rules_access_secom.json | 门禁（中興保全 SECOM） | Tomcat 栈指纹 / Tomcat 管理器暴露 | 08-24 门禁线 |
| rules_ews_printer.json | EWS 打印机 | VNC 面板/账户管理/备份密码/固件升级/配置导出 .ucf | Lexmark 实战 5 端点（2026-07），可迁移至 EWS 架构打印机厂 |
| rules_superpw_only.json | 超级密码单点 | 兑换码未授权泄露（拆出单规则复跑用） | 08-24 新前端线拆出 |
| rules_generic.json | 通用模板 | 配置导出/backup/路径穿越/API 敏感字段/RTSP | 新线起步模板 |

## 3. 大厂黑名单（准备阶段直接排除，全部是重复重灾区）

```
NVR/IPC：海康 HIKVISION / 大华 Dahua / 宇视 Uniview / 雄迈 xiongmaitech / 天地伟业 Tiandy / SAMSUNG / Wisenet / CP PLUS
打印机：Lexmark / 三星 Samsung / 佳能 Canon / 理光 Ricoh / 兄弟 Brother / HP / Xerox / Epson
网络设备：TP-Link / 华为 Huawei / 中兴 ZTE / Cisco / H3C / 锐捷 / Netgear / 华硕 Asus
工控：西门子 Siemens / 施耐德 Schneider / 罗克韦尔 Rockwell
NAS：群晖 Synology / 威联通 QNAP
```

例外：大厂的新端点新攻击面（如 Lexmark VNC 面）可进，但默认跳过。冷门特征 = 白牌固件线（Boa/webs 系）、区域小厂、贴牌 OEM。

## 4. 脚本与通道

- 脚本：`<包根>/tools/scripts/`（cnvd_recon.py / cnvd_check.py v2）；字典：`<包根>/tools/rules/`；key：`<包根>/api_keys.json`（recon 自动按 包根→当前目录→环境变量 CNVD_KEYS_FILE 顺序查找）
- FOFA 通道（全部在 api_keys.json 的 channels 数组配置，支持任意数量）：按顺序自动尝试，失败自动切下一个；格式兼容 FOFA 官方 `/api/v1/search/all?key&qbase64` 或常见中转 `?key&query` 两种，配 base_url/search_path/key_param/query_param 即可
- 工作目录：`<工作根>/cnvd/<产品线>/<日期>/`，状态文件 progress.md + actions.jsonl（轻量两件套，agent 派发留痕）
- 日志：按本机习惯的日志目录落 `cnvd-YYYYMMDD.log`

## 5. 合规红线（不变）

```
绝对不做：
  ❌ 修改任何配置 / 删除任何数据
  ❌ 下载敏感文件到本地（仅确认存在即可）
  ❌ 暴力破解 / 横向渗透
  ❌ 提交前对外公开漏洞细节
  ❌ 扫描政府/军事/关键基础设施（无授权）
必须做：
  ✅ 只读操作（GET/OPTIONS/DESCRIBE/LIST）
  ✅ 单 IP 间隔 ≥1s（脚本已固化）
  ✅ 完整操作日志
  ✅ 发现漏洞仅用于 CNVD 提交
```

## 6. 看板

```
| 产品线 | 厂商 | 存量 | 命中 | 案例 | 查重 | 报告 | 审核状态 |
|--------|------|------|------|------|------|------|----------|
```

**收尾**：① 会话收尾巡检主目录 ② 日志归档 ③ 出洞/经验写记忆（漏洞挖掘域）+ 更新 MEMORY.md ④ 每轮定级交用户拍板。
