# 阶段1 抽验 agent 派发模板（Boa 大组）

任务：cnvd 阶段1 — 独立抽验（只读复验 findings）
输入（必读）：<工作目录>\findings_xxx.csv（只读 ip,port,rule_id,url 四列，禁止看 snippet 列防预判）
输出（必写）：<工作目录>\verify_report.json

检查项（一次性穷举，每 case 全做）：
  □ no_cookie_repro：无 cookie 二次请求可复现（urllib/requests 裸 GET 无会话）
  □ real_data：内容是真实设备数据非 mock/占位（比对 UID 格式/设备型号与固件自洽；Config.json 应含 ZWP2P UID 形如 XXXXXX-XXXXXX-XXXXXX）
  □ honeypot：蜜罐判定+理由（云段 IP 优先怀疑；读到的数据与 NVR 设备自洽=真机加分；理由必须写）
  □ device_model：设备型号/固件特征（响应内容可推断的型号，如 p6spro 相关）
  □ geo：ip-api 查归属 isp/as/cloud（每 case 1 次，间隔 ≥1.5s）
红线：
  □ 只读 GET/POST（ONVIF SOAP 无副作用）
  □ 单 IP 间隔 ≥1s；不下载敏感文件；不触发任何写操作
  □ 不重测 RTSP 拉流（只确认 OPTIONS 200 即可）
产出要求：按 schema 逐字段；excluded 必须带 fail_reason 证据；禁止"没发现"式结论

schema:
case_id / verdict(confirmed|excluded|needs_review) / checks{no_cookie_repro, real_data, honeypot(带理由), device_model, geo{isp,as,cloud}} / evidence{snippet} / fail_reason

校验标准：high 100% 抽验 / mid ≥20% 抽验；confirmed 才进案例池
