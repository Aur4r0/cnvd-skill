# CNVD 挖洞 Skill 便携包（v2.0）

> 用途：把「CNVD 通用型未授权漏洞广扫」这套 skill 完整搬到另一台电脑使用。
> 打包日期：2026-09-13 ｜ 适用：Windows（脚本本身跨平台，Linux/macOS 亦可跑）
>
> 📖 文档导航：[仓库主页](README.md) ｜ [使用教程](docs/使用教程.md) ｜ [规则编写指南](docs/规则编写指南.md) ｜ [FAQ](docs/FAQ.md) ｜ [更新日志](CHANGELOG.md) ｜ [English](README_EN.md)

---

## 一、包里有什么

```
cnvd-skill-便携包/
├── README-移植说明.md          ← 本文件
├── 校验.bat                    ← 双击运行：环境自检 + 冒烟测试
├── api_keys.json               ← FOFA 通道 key 模板（占位符，用前必须填自己的 key）
├── skills/
│   └── cnvd/SKILL.md           ← skill 本体（流程/原则/字典说明）
├── tools/
│   ├── scripts/                ← 9 个 Python 脚本（纯标准库，零 pip 依赖）
│   │   ├── cnvd_recon.py       ← 阶段0 测绘：FOFA 多通道拉存量
│   │   ├── cnvd_check.py       ← 阶段1 验证：HTTP/RTSP/FTP 三类探针 + 双差分判据
│   │   ├── rtsp_probe.py / rtsp_live_verify.py / verify_rtsp2.py   ← RTSP 专项
│   │   ├── verify_newfe_A.py / probe_newfe_A_bodies.py             ← 新前端线抽验
│   │   ├── verify_newfe_B.py / bing_search.py                      ← 抽验 + 厂商检索
│   └── rules/                  ← 端点字典库（8 文件 28 条规则，核心资产）
└── 示例产出/                   ← 格式样例（已脱敏，无真实设备 IP）
    ├── progress.md             ← 状态机写法样例
    ├── intel.md                ← 情报台账写法样例
    ├── verify_prompt_template.md  ← 抽验 agent 派发模板（可复用）
    ├── targets_样例-脱敏.csv    ← check 的输入格式（ip,port 两列）
    ├── findings_样例-脱敏.csv   ← check 的输出格式（别当输入用）
    └── 全部案例IP-格式说明.txt  ← 报告附件格式说明
```

## 二、移植三步

**第 1 步：装 Python（唯一硬性依赖）**

- 需要 Python 3.8+（推荐 3.12），脚本纯标准库，**不需要 pip install 任何东西**
- Windows：https://python.org 下载安装，装时勾选 "Add python.exe to PATH"
- 验证：命令行敲 `python --version` 有输出即成功

**第 1.5 步：填自己的 FOFA key（必做）**

包内 `api_keys.json` 是**占位模板**，所有通道的 `key` 字段都是 `REPLACE_ME`。开工前：

1. 准备 FOFA 查询通道（官方 fofa.info 会员，或任意提供官方/中转格式 API 的代理站）
2. 编辑 `api_keys.json`，在 `channels` 数组里配置你的通道：
   - `base_url`：中转站地址（如 `https://your-proxy.com`）
   - `search_path`：查询接口路径（官方格式一般是 `/api/v1/search/all`，中转格式看你的站文档）
   - `key_param`：key 参数名（一般是 `key`，个别站是 `api_key`）
   - `query_param`：查询参数格式（官方格式用 `qbase64`，中转明文格式用 `query`）
   - `key`：你的 API key
   - `enabled`：`true` 启用该通道
3. 多通道自动按顺序尝试：第一个失败自动切下一个。要加备用站就复制一项改个 name 和 base_url。

> 想先跑通流程再配 key？可以：脚本的 `--help`、字典、check 扫描都不需要 key，只有 recon 拉资产需要。

**第 2 步：放入 Claude Code（要用 skill 触发词的话）**

把 `skills/cnvd/` 整个文件夹复制到本机 Claude Code 的 skills 目录（默认 `~/.claude/skills/cnvd/`，Windows 即 `C:\Users\<你的用户名>\.claude\skills\cnvd\`）。
重开 Claude Code 会话，说「cnvd」即触发。

> 不用 Claude Code 也行：SKILL.md 就是一份完整的操作手册（流程+判据+合规红线），
> 人肉照着走 + 直接用 tools/scripts 里的脚本，一样能干活。

**第 3 步：自检**

双击 `校验.bat`。全 ✅ 即可开工。会检查：
① Python 可用 ② 脚本能跑（`--help`）③ key 读得到 ④ FOFA 通道实测发一条小查询

## 三、开工命令（最短路径）

```bat
cd tools\scripts

:: 1) 测绘：拉某类产品线存量（preset 可选 nvr/printer/industrial/network/access/nas/conference）
python cnvd_recon.py --preset nvr --out stage0_nvr.csv

:: 2) 整理 targets.csv（表头 ip,port）后批量验证
python cnvd_check.py --targets targets.csv --rules ..\rules\rules_boa.json --geo --out findings.csv

:: 3) 命中 ≥10 → 按 SKILL.md §1.3 派 agent 查重+抽验
```

各脚本详细参数：`python cnvd_xxx.py --help`。

**⚠️ 输入格式区分**（新手最容易搞反）：
- `cnvd_check.py --targets` 要的是 **targets 格式**：只有 `ip,port` 两列（见 `示例产出\targets_样例-脱敏.csv`）
- `示例产出\findings_样例-脱敏.csv` 是 check 的**输出**格式，不是输入——别拿它当 targets 用
- 四列版（`ip,port,rule_id,url`）是给 §1.3 抽验 agent 的输入格式

**各脚本用途速查**：

| 脚本 | 用途 | 常用参数 |
|------|------|----------|
| cnvd_recon.py | 测绘：FOFA 拉存量 | `--preset nvr` / `--query '...'` / `--out` |
| cnvd_check.py | 批量验证：HTTP/RTSP/FTP | `--targets` `--rules` `--geo` `--out` |
| verify_newfe_A.py | 新前端线A（密码找回链）独立抽验 | `--csv` `--out` |
| verify_newfe_B.py | 新前端线B（泄露面）独立抽验 | `--csv` `--out` |
| verify_rtsp2.py | RTSP 批量补验（OPTIONS+DESCRIBE） | `--csv` `--out` |
| probe_newfe_A_bodies.py | 结构探查：重取原始 body 头部 | `--csv` `--out` |
| rtsp_probe.py / rtsp_live_verify.py | RTSP 单点探测 / 真拉流四步确认 | 参数在脚本头部 |
| bing_search.py | Bing 检索（厂商查重辅助） | 参数在脚本头部 |

> 速度参考：单 IP 串行 ≥1s 是合规红线；100 台未响应资产约需 10-15 分钟，属正常。想先通流程，用 5-10 台的**可达**目标测。

## 四、可调项（换机后建议检查）

| 项 | 说明 |
|----|------|
| `api_keys.json` | **占位模板**，用前必须填自己的 FOFA key（见第 1.5 步）；在 `channels` 数组里配置，支持任意数量通道，自动按顺序尝试 |
| FOFA 通道地址 | 全部在 `api_keys.json` 的 `channels` 里配，改 json 不动代码 |
| 报告输出 | **统一落桌面**：`Desktop\cnvd\<厂商>\<日期>\`（拿到报告即在这里找）；工作目录用 `--out` 自定 |
| 校验.bat 的 python 命令 | 若本机用 `py` 启动器，把 bat 里的 `python` 批量替换为 `py` |

## 五、合规红线（务必一并移植）

```
只做：只读 GET/OPTIONS/DESCRIBE/LIST ｜ 单 IP 间隔 ≥1s ｜ 完整操作日志 ｜ 仅用于 CNVD 提交
禁止：改配置/删数据 ｜ 下载敏感文件 ｜ 暴力破解/横向 ｜ 提交前公开细节 ｜ 无授权扫政府/军事/关基
```

## 六、常见问题

**Q：运行报 `ModuleNotFoundError`？**
不应该发生——所有脚本纯标准库。若出现，检查是否 Python 环境太旧（<3.8）。

**Q：recon 报「所有通道均失败」或 key 报错？**
若还没填自己的 key（api_keys.json 里还是 REPLACE_ME），recon 必然失败——这是预期行为，先完成第 1.5 步。
已填 key 仍失败：检查 `base_url` / `search_path` / `query_param` 三项是否和你的中转站文档一致；不同中转站格式不一样，配错了会 404 或返回空。所有通道都挂 = 通道侧问题，隔天再试。

**Q：输出文件在哪？**
各脚本现在都用「相对路径默认值 + 命令行参数」：不传参时输出落在**当前工作目录**；用 `--out 你的路径` 指定到别处。
报告按 SKILL.md §1.4 统一放桌面 `cnvd\<厂商>\<日期>\`。

**Q：中文输出乱码？**
脚本已内置 UTF-8 输出修正；若仍乱码，命令行先执行 `chcp 65001`。

**Q：check 扫出来一堆 mock/cloud_suspect 标记？**
正常，那是防误报机制在工作。`mock=True` 或 `cloud_suspect=True` 的条目要人工/agent 复核后再计入案例。

---
*本包示例数据已脱敏（RFC 5737 保留段），不含任何真实目标资产与个人信息；FOFA key 为占位模板，需使用者在本地自行填写。*
