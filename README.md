<div align="center">

# cnvd-skill

**CNVD 通用型未授权漏洞广扫 · 便携工具包**

冷门产品线 × 预置端点字典 × 批量只读验证 —— 命中 ≥10 即一个洞

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#环境要求)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#环境要求)

[English](README_EN.md) · [使用教程](docs/使用教程.md) · [规则编写指南](docs/规则编写指南.md) · [FAQ](docs/FAQ.md) · [更新日志](CHANGELOG.md)

</div>

---

## 这是什么

一套面向 **CNVD 通用型未授权漏洞** 的批量挖掘工作流工具包：

- **Skill 本体**（`skills/cnvd/SKILL.md`）——完整流程 / 原则 / 判据 / 合规红线，不用 Claude Code 也能当操作手册人肉照着走
- **9 个 Python 脚本**——纯标准库、零 pip 依赖，覆盖 **测绘 → 定级检测 → 查重抽验** 全链路
- **8 文件 28 条端点字典**——来自实战验证的未授权端点，跨厂商可迁移（本包核心资产）
- **脱敏示例 + 一键自检**——`示例产出/` 展示全部中间产物格式，`校验.bat` 双击完成环境自检与冒烟

核心思路：**不做固件级深挖，做端点级的横向覆盖**。挑一个冷门产品线，用预置字典批量验证同类设备，命中 ≥10 台即够一个 CNVD 通用型漏洞的案例量。

**运行语义（2.3）**：**无产出不停** —— 唯一合法停机条件 = 已挖到 ≥1 个可提交级洞并落盘（命中 ≥10 + 查重无重复 + 复验通过 + 厂商资质达标 + 报告完成）。在此之前，换线 ≠ 收工：没出货就换下一条产品线，多条线重复就继续换，直到出货或用户喊停。合规红线在连续作业下执行强度不变。

**厂商资质门槛（2.3）**：CNVD 发证硬门槛 = 通用型 + 厂商**注册资本实缴 > 5000 万人民币** + 优先国内。甜点区 = **注册资本过线但知名度低的中型/小厂**——大厂是重复重灾区（白干），小厂不够发证资格。准备阶段须核验厂商工商信息（§1.1a），报告须含「厂商信息」段。

**复现规范（2.3 · 反虚构铁律）**：复现步骤以最简单形式呈现——**优先 curl / 浏览器直接访问**；curl 无法表达时（特殊头部/POST/WebSocket）贴**真实数据包**。**禁止任何虚构**：所有请求/响应必须是实操原文，所有复现方式必须亲自跑过且能复现，没跑过的步骤不写进报告（详见 SKILL.md §1.4a）。

## 工作流

```
准备(10min) → 测绘(recon) → 批量验证(check) → 查重+抽验(agent) → 报告 → 下一条线
```

| 阶段 | 工具 | 产出 |
|------|------|------|
| 0 测绘 | `cnvd_recon.py` | 目标存量 CSV（FOFA 多通道拉取） |
| 1 验证 | `cnvd_check.py` | `findings.csv`（三重防误报） |
| 1.5 查重+抽验 | `verify_*.py` + 派发模板 | `verify_report.json` |
| 2 报告 | SKILL.md §1.4 流程 | 提交版 + 复现版报告 + 全量案例 IP |

## 特性

- **三类协议只读探针**：HTTP（GET/POST 双差分）、RTSP（严格 SDP 判据）、FTP（匿名 230 探测）
- **双差分防误报**：HTTP 命中后自动二次无 cookie 请求，结果不可复现即丢弃
- **蜜罐排除**：内置 ip-api 归属查询，云厂商段自动标 `cloud_suspect` 供人工复核
- **严格 RTSP 判据**：必须 `DESCRIBE 200` 且 SDP 含 `v=0` + `m=video/audio`；OPTIONS-only 一律丢弃（实战返工教训固化）
- **FOFA 多通道**：支持任意数量通道（官方格式 / 中转格式均可），失败自动切下一个
- **断点续跑**：`--resume` 跳过已完成目标，中断不丢进度
- **合规内置**：单 IP 严格串行 + 间隔 ≥1s（代码级固化），全链路只读
- **零依赖**：只需 Python 3.8+，不装任何第三方包

## 目录结构

```
cnvd-skill/
├── README.md                    ← 本文件（仓库首页）
├── README-移植说明.md            ← 便携包移植说明（换机部署看这篇）
├── README_EN.md                 ← English overview
├── CHANGELOG.md                 ← 版本记录
├── LICENSE                      ← MIT
├── 校验.bat                     ← 双击运行：环境自检 + 冒烟测试
├── api_keys.json                ← FOFA 通道 key 模板（占位符，用前必须填自己的 key）
├── skills/
│   └── cnvd/SKILL.md            ← Skill 本体（流程 / 原则 / 判据 / 合规红线）
├── tools/
│   ├── scripts/                 ← 9 个 Python 脚本（纯标准库，零 pip 依赖）
│   │   ├── cnvd_recon.py        ← 阶段0 测绘：FOFA 多通道拉存量
│   │   ├── cnvd_check.py        ← 阶段1 验证：HTTP/RTSP/FTP 三类探针 + 双差分判据
│   │   ├── verify_newfe_A.py    ← 新前端线A（密码找回链）抽验
│   │   ├── verify_newfe_B.py    ← 新前端线B（泄露面）抽验
│   │   ├── probe_newfe_A_bodies.py ← 结构探查：重取原始 body 头部
│   │   ├── verify_rtsp2.py      ← RTSP 批量补验（OPTIONS+DESCRIBE）
│   │   ├── rtsp_probe.py        ← RTSP 单点探测（命令行直用）
│   │   ├── rtsp_live_verify.py  ← RTSP 真拉流四步确认（DESCRIBE→SETUP→PLAY→RTP）
│   │   └── bing_search.py       ← Bing 检索（厂商查重辅助）
│   └── rules/                   ← 端点字典库（8 文件 28 条规则，核心资产）
│       ├── rules_boa.json       ← NVR（Boa 固件线）
│       ├── rules_newfe.json     ← 新前端 NVR/IPC
│       ├── rules_access_menjin.json ← 门禁（门禁专家）
│       ├── rules_access_drid.json   ← 门禁（Dr.ID）
│       ├── rules_access_secom.json  ← 门禁（SECOM）
│       ├── rules_ews_printer.json   ← EWS 打印机
│       ├── rules_superpw_only.json  ← 超级密码单点（拆出复跑用）
│       └── rules_generic.json   ← 通用起步模板（新线用）
├── docs/
│   ├── 使用教程.md               ← 从零跑通一条产品线
│   ├── 规则编写指南.md            ← 自定义端点字典的方法
│   └── FAQ.md                   ← 常见问题
└── 示例产出/                    ← 格式样例（已脱敏，RFC 5737 保留段）
    ├── progress.md              ← 状态机写法样例
    ├── intel.md                 ← 情报台账写法样例
    ├── verify_prompt_template.md ← 抽验 agent 派发模板
    ├── targets_样例-脱敏.csv     ← check 的输入格式（ip,port 两列）
    ├── findings_样例-脱敏.csv    ← check 的输出格式
    └── 全部案例IP-格式说明.txt    ← 报告附件格式说明
```

## 快速开始

### 环境要求

- **Python 3.8+**（推荐 3.12）——唯一硬性依赖，脚本零第三方包
- Windows / Linux / macOS 均可（`校验.bat` 仅 Windows）

### 三步跑起来

**第 1 步：装 Python**（已有可跳过）

到 https://python.org 下载安装，装时勾选 "Add python.exe to PATH"。验证：命令行敲 `python --version` 有输出即成功。

**第 2 步：填自己的 FOFA key（必做）**

包内 `api_keys.json` 是**占位模板**（所有 key 都是 `REPLACE_ME`）。编辑 `channels` 数组配置你的查询通道：

```json
{
  "channels": [
    {
      "name": "primary",
      "enabled": true,
      "base_url": "https://你的中转站地址",
      "search_path": "/api/v1/search/all",
      "key_param": "key",
      "query_param": "qbase64",
      "key": "你的key"
    }
  ]
}
```

- `query_param`：官方格式用 `qbase64`（查询语句 base64 编码），中转明文格式用 `query`
- `key_param`：一般是 `key`，个别站是 `api_key`
- 不同中转站格式不一样，对照你的站文档配置；配错会 404 或返回空
- 支持任意数量通道：自动按顺序尝试，失败切下一个。加备用站复制一项改 `name` / `base_url` 即可

> 不想先配 key？`--help`、字典（rules）、check 扫描都不需要 key，只有 recon 拉资产需要。

**第 3 步：自检**

双击 `校验.bat`。全 ✅ 即可开工。会检查：① Python 可用 ② 各脚本能跑 ③ key 读得到 ④ FOFA 通道实测发一条小查询。

### 最短命令

```bat
cd tools\scripts

:: 1) 测绘：拉某类产品线存量（preset 可选 nvr/printer/industrial/network/access/nas/conference）
python cnvd_recon.py --preset nvr --out stage0_nvr.csv

:: 2) 整理 targets.csv（表头 ip,port 两列）后批量验证
python cnvd_check.py --targets targets.csv --rules ..\rules\rules_boa.json --geo --out findings.csv

:: 3) 命中 ≥10 → 按 SKILL.md §1.3 派 agent 查重 + 抽验
```

> ⚠️ **输入格式别搞反**：`cnvd_check.py --targets` 要的是 targets 格式（**只有 `ip,port` 两列**）；`findings_样例-脱敏.csv` 是 check 的**输出**格式，四列版（`ip,port,rule_id,url`）才是给抽验脚本的输入。

## 脚本速查

| 脚本 | 用途 | 常用参数 |
|------|------|----------|
| `cnvd_recon.py` | 测绘：FOFA 多通道拉存量 | `--preset nvr` / `--query '...'` / `--out` / `--list-presets` / `--list-channels` |
| `cnvd_check.py` | 批量验证：HTTP/RTSP/FTP | `--targets` `--rules` `--geo` `--resume` `--out` |
| `verify_newfe_A.py` | 新前端线A（密码找回链）独立抽验 | `--csv` `--out` |
| `verify_newfe_B.py` | 新前端线B（泄露面）独立抽验 | `--csv` `--out` |
| `verify_rtsp2.py` | RTSP 批量补验（OPTIONS+DESCRIBE） | `--csv` `--out` |
| `probe_newfe_A_bodies.py` | 结构探查：重取原始 body 头部 | `--csv` `--out` |
| `rtsp_probe.py` | RTSP 单点探测 | `python rtsp_probe.py <ip>:<port> ...` |
| `rtsp_live_verify.py` | RTSP 真拉流四步确认 | `python rtsp_live_verify.py <ip>:<port> ...` |
| `bing_search.py` | Bing 检索（厂商查重辅助） | 直接运行，内置预设查询集 |

各脚本完整参数：`python cnvd_xxx.py --help`。

> 速度参考：**单 IP 串行 ≥1s 是合规红线**（代码已固化）；100 台未响应资产约需 10-15 分钟，属正常。

## 端点字典（核心资产）

| 文件 | 产品线 | 端点 | 来源 |
|------|--------|------|------|
| `rules_boa.json` | NVR/HVR（Boa 固件） | Config.json(UID) / ONVIF / RTSP / FTP 匿名 | 中维 ZWP2P 实战 |
| `rules_newfe.json` | 新前端 NVR/IPC | Config.json(UID) / 超级密码兑换码 / 找回接口 / RTSP / ONVIF | 新前端线（p6scloud 系） |
| `rules_access_menjin.json` | 门禁（门禁专家） | 固件指纹 / 登录页预填默认账密 | 门禁线实战 |
| `rules_access_drid.json` | 门禁（Dr.ID） | IIS 栈指纹 / o_*.aspx 未授权候选 | 门禁线实战 |
| `rules_access_secom.json` | 门禁（SECOM） | Tomcat 栈指纹 / Tomcat 管理器暴露 | 门禁线实战 |
| `rules_ews_printer.json` | EWS 打印机 | VNC 面板 / 账户管理 / 备份密码 / 固件升级 / 配置导出 | Lexmark EWS 实战（可迁移同类架构） |
| `rules_superpw_only.json` | 超级密码单点 | 兑换码未授权泄露 | 新前端线拆出 |
| `rules_generic.json` | 通用模板 | 配置导出 / backup / 路径穿越 / API 敏感字段 / RTSP | 新线起步模板 |

编写自定义规则 → [规则编写指南](docs/规则编写指南.md)。

## 合规红线（务必遵守）

```
只做：只读 GET/OPTIONS/DESCRIBE/LIST ｜ 单 IP 间隔 ≥1s ｜ 完整操作日志 ｜ 仅用于 CNVD 提交
禁止：改配置/删数据 ｜ 下载敏感文件 ｜ 暴力破解/横向 ｜ 提交前公开细节 ｜ 无授权扫政府/军事/关基
```

- 本工具**只做未授权访问验证**（证明"能读到什么"），不提供任何写入 / 利用 / 持久化能力
- 使用前确认你对目标资产**有测试授权**，或目标为公开致谢范围
- 漏洞细节在平台披露前不得公开

## 免责声明

本工具仅供**授权范围内的安全测试**与 **CNVD 等平台的正规漏洞提交**使用。使用者应确保其行为符合《网络安全法》等相关法律法规，并自行承担因不当使用产生的一切责任。作者不对任何滥用行为负责。

## 文档索引

| 文档 | 内容 |
|------|------|
| [README-移植说明.md](README-移植说明.md) | 便携包移植三步曲（换机部署必读） |
| [docs/使用教程.md](docs/使用教程.md) | 从零跑通一条产品线：测绘→验证→抽验→报告全流程实录 |
| [docs/规则编写指南.md](docs/规则编写指南.md) | 端点字典 JSON 结构与判据设计方法 |
| [docs/FAQ.md](docs/FAQ.md) | 常见问题与排坑 |
| [CHANGELOG.md](CHANGELOG.md) | 版本记录 |

---

*本包示例数据已脱敏（RFC 5737 保留段），不含任何真实目标资产与个人信息；FOFA key 为占位模板，需使用者在本地自行填写。*
