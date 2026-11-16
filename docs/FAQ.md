# FAQ —— 常见问题与排坑

---

## 安装 / 环境

**Q：运行报 `ModuleNotFoundError`？**

不应该发生——所有脚本纯标准库。若出现：检查 Python 版本是否 ≥3.8（`python --version`）。

**Q：脚本能跑但中文乱码？**

脚本已内置 UTF-8 输出修正；若仍乱码，命令行先执行 `chcp 65001`。

**Q：本机用 `py` 启动器而不是 `python`？**

把 `校验.bat` 里的 `python` 批量替换为 `py` 即可。

**Q：Linux / macOS 能用吗？**

能。脚本本身跨平台；只有 `校验.bat` 是 Windows 专用——手动依次跑各脚本 `--help` 即等效自检。

---

## FOFA / recon

**Q：recon 报「所有通道均失败」或 key 报错？**

- 若还没填自己的 key（`api_keys.json` 里还是 `REPLACE_ME`）：必然失败，这是预期行为，先完成配置
- 已填 key 仍失败：检查 `base_url` / `search_path` / `query_param` 三项是否和你的中转站文档一致。不同中转站格式不一样，配错了会 404 或返回空
- 所有通道都挂 = 通道侧问题，隔天再试

**Q：怎么加备用通道？**

复制 `channels` 数组里一项，改 `name` 和 `base_url`（新 key 若不同也改），脚本自动按顺序尝试，失败切下一个。

**Q：`--list-channels` 和 `--list-presets` 是干什么的？**

分别列出当前配置的通道和内置的产品线查询预设，配置完先跑一下确认。

---

## check / 验证

**Q：跑得很慢？**

正常。**单 IP 串行 ≥1s 是合规红线**（代码级固化，不要调低 `--interval`）。100 台未响应资产约需 10-15 分钟。想先通流程，用 5-10 台**可达**目标测。

**Q：扫出来一堆 mock / cloud_suspect 标记？**

正常，那是防误报机制在工作。`mock=True`（命中占位/伪造提示词）或 `cloud_suspect=yes`（目标属云厂商段，可能是研究环境/蜜罐）的条目，要人工/agent 复核后再计入案例。

**Q：断点续跑怎么用？**

`--resume` + 指定同一个 `--out` 文件。进度记在同目录的 `<out>.scanned.csv` 台账里：每扫完一个目标（**包括零命中的**）就落一行，续跑时精确跳过。中断了直接重跑加 `--resume` 即可。

命中会同时增量写进 findings，所以进程被杀也不会丢已完成目标的结果。想指定台账位置用 `--ledger`。

> 没有台账的旧 run（2.3 及以前产生的）会自动回退为「按 findings 推导已完成目标」，此时零命中目标会被重扫一遍。

**Q：RTSP 命中为什么这么少？**

严格判据是有意的：必须 `DESCRIBE 200` 且 SDP 含 `v=0` + `m=video/audio`。OPTIONS-only 的响应一律丢弃——它们进报告只会拉低可信度（实战返工教训）。

**Q：输入格式到底哪个是哪个？**

- `cnvd_check.py --targets`：**targets 格式**，只有 `ip,port` 两列
- `findings_样例-脱敏.csv`：check 的**输出**格式，别当输入用
- 四列版（`ip,port,rule_id,url`）：给抽验脚本（verify_*）的输入格式

---

## 抽验 / 报告

**Q：抽验脚本报「未知 rule_id」？**

每个抽验脚本只认自己支持的 rule_id（如 `verify_newfe_A.py` 认 `superpw-qr` / `saveq-open`）。确认输入 CSV 的 rule_id 与脚本匹配，或换对应的 verify 脚本。

**Q：命中 ≥10 了，接下来干什么？**

按 SKILL.md §1.3：派一个独立 agent 做**查重（四源）+ 独立复验（随机 3-5 台）**。`duplicate` → 换点或换线；`no_duplicate + confirmed` → 写报告。

**Q：报告放哪？**

统一 `Desktop\cnvd\<厂商>\<日期>\`（SKILL.md §1.4），每洞两版（提交版/复现版），案例 IP 全量导出 `全部案例IP.txt` 同目录。**定级交用户拍板**。

**Q：截图谁做？**

默认不做（脚本不截图）——用户自己复现看。需要证据图时人工补。

---

## 合规 / 边界

**Q：这个工具能"打"下目标吗？**

不能，也不设计来打。它**只做未授权访问验证**（证明"能读到什么"），全链路只读（GET/OPTIONS/DESCRIBE/LIST），不提供任何写入/利用/持久化能力。

**Q：扫哪些目标是合规的？**

你对它有**测试授权**、或属于 CNVD 提交所需的公开暴露资产样本、或明确排除政府/军事/关键基础设施（无授权时）。拿不准就不扫。

**Q：发现洞了能先发博客吗？**

不能。**提交前公开细节**是明确红线——先走 CNVD 提交流程，平台披露后再谈。

---

## 其他

**Q：这个包和本机 Claude Code skill 什么关系？**

`skills/cnvd/SKILL.md` 就是 Claude Code skill 的本体：把 `skills/cnvd/` 复制到 `~/.claude/skills/` 下、重开会话、说「cnvd」即可触发。不用 Claude Code 也能用——SKILL.md 本身是一份完整操作手册。

**Q：能贡献新规则吗？**

欢迎。新洞实战确认后按 `docs/规则编写指南.md` 的格式追加，标注来源+判据+日期。
