#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CNVD 阶段0 反向测绘 —— FOFA 多通道资产查询
通道全部从 api_keys.json 的 channels 数组读取，支持任意兼容 FOFA 官方格式或常用中转格式的 API。
用法:
  python cnvd_recon.py --preset nvr [--size 1000] [--max 3000] [--out out.csv]
  python cnvd_recon.py --query 'title="NVR"' [--query ...] [同上]
  python cnvd_recon.py --list-presets
  python cnvd_recon.py --list-channels
"""
import argparse, base64, csv, json, os, sys, time
import urllib.request, urllib.parse

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

def _find_keys_file():
    """按 便携包根目录 → 当前目录 → 环境变量 CNVD_KEYS_FILE 顺序找 api_keys.json"""
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), "api_keys.json"),   # 便携包根目录
        os.path.join(os.getcwd(), "api_keys.json"),              # 当前目录
        os.environ.get("CNVD_KEYS_FILE", ""),                    # 环境变量指定
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return candidates[0]

KEYS_FILE = _find_keys_file()
DEFAULT_FIELDS = ["ip", "port", "host", "title", "server"]

PRESETS = {
    "nvr": {"label": "视频监控 NVR/DVR/IPC", "queries": [
        'title="NVR" && (port="80" || port="8080")',
        'title="DVR" && (port="80" || port="8080")',
        'title="网络摄像机"',
    ]},
    "printer": {"label": "打印机/复印机/MFP", "queries": [
        'title="Embedded Web Server" && port="80"',
        'title="打印机" && port="80"',
        'app="CUPS"',
        'title="Xerox" && port="80"',
    ]},
    "industrial": {"label": "工控 HMI/PLC/SCADA", "queries": [
        'title="HMI" && port="80"',
        'title="SCADA" && port="80"',
        'protocol="modbus"',
        'title="PLC" && port="80"',
    ]},
    "network": {"label": "网络设备 路由器/交换机/AC", "queries": [
        'title="路由器" && port="80"',
        'title="AC控制器"',
        'title="交换机" && port="80"',
        'app="TP_LINK-Router"',
    ]},
    "access": {"label": "门禁/考勤/闸机", "queries": [
        'title="门禁"', 'title="考勤"', 'title="闸机"',
    ]},
    "nas": {"label": "NAS/存储", "queries": [
        'title="Synology"', 'title="QNAP"', 'title="NAS" && port="80"',
    ]},
    "conference": {"label": "会议终端/视频会议", "queries": [
        'title="视频会议"', 'title="Yealink"', 'title="Meeting Room" && port="80"',
    ]},
}

def load_channels():
    """从 api_keys.json 读取所有 enabled 的通道配置"""
    with open(KEYS_FILE, encoding="utf-8") as f:
        cfg = json.load(f)
    channels = cfg.get("channels", [])
    return [c for c in channels if c.get("enabled", True)]

def http_get_json(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))

def query_channel(ch, query, page, size, fields):
    """通用通道查询：根据通道配置自动决定参数格式"""
    base = ch["base_url"].rstrip("/")
    path = ch.get("search_path", "/api/v1/search/all")
    key_param = ch.get("key_param", "key")
    query_param = ch.get("query_param", "qbase64")
    key = ch["key"]

    if query_param == "qbase64":
        q_enc = base64.b64encode(query.encode("utf-8")).decode()
        q_enc = urllib.parse.quote(q_enc)
    else:
        q_enc = query

    url = f"{base}{path}?{key_param}={key}&{query_param}={q_enc}&size={size}&page={page}&fields={','.join(fields)}"
    res = http_get_json(url, 120)
    if isinstance(res, dict) and (res.get("error") or "维护" in str(res)):
        raise RuntimeError(f"通道异常: {res.get('error') or res}")
    return res

def extract_rows(res, fields):
    out = []
    for r in res.get("results") or []:
        if isinstance(r, dict):
            out.append([r.get(f, "") for f in fields])
        else:
            out.append(list(r)[:len(fields)])
    return out

def run_query(query, size, max_total, fields, channels):
    """按通道顺序尝试，直到某个通道返回数据"""
    rows, page = [], 1
    last_err = None
    while len(rows) < max_total:
        batch = None
        for ch in channels:
            try:
                res = query_channel(ch, query, page, size, fields)
                batch = extract_rows(res, fields)
                if batch:
                    break
            except Exception as e:
                last_err = e
                continue
        if batch is None:
            raise RuntimeError(f"所有通道均失败: {last_err}")
        rows.extend(batch)
        page += 1
        if len(batch) < size:
            break
        time.sleep(0.5)
    return rows[:max_total]

def main():
    p = argparse.ArgumentParser(description="CNVD 阶段0 反向测绘(FOFA 多通道)")
    p.add_argument("--preset", choices=list(PRESETS))
    p.add_argument("--query", action="append", help="可多次")
    p.add_argument("--size", type=int, default=1000)
    p.add_argument("--max", type=int, default=3000, dest="max_total")
    p.add_argument("--channel", help="指定通道 name（默认 auto 按 channels 数组顺序尝试）")
    p.add_argument("--fields", default=",".join(DEFAULT_FIELDS))
    p.add_argument("--out")
    p.add_argument("--list-presets", action="store_true")
    p.add_argument("--list-channels", action="store_true", help="列出当前配置的通道")
    args = p.parse_args()

    if args.list_presets:
        for k, v in PRESETS.items():
            print(f"  {k:12s} {v['label']}")
            for q in v["queries"]:
                print(f"      {q}")
        return

    channels = load_channels()
    if args.list_channels:
        print(f"== 已启用通道 ({len(channels)} 个) ==")
        for ch in channels:
            print(f"  - {ch['name']:12s} {ch['base_url']}  ({ch.get('query_param', 'qbase64')})")
        return

    if not channels:
        print("== 错误：api_keys.json 里没有 enabled=true 的通道 ==")
        print("   请编辑 api_keys.json，填入你的 FOFA 中转站 key 和地址")
        sys.exit(1)

    if args.channel:
        channels = [c for c in channels if c["name"] == args.channel]
        if not channels:
            print(f"== 错误：找不到名为 '{args.channel}' 的通道 ==")
            sys.exit(1)

    queries = list(args.query or [])
    if args.preset:
        queries += PRESETS[args.preset]["queries"]
    if not queries:
        p.error("需要 --preset 或 --query")
    fields = [f.strip() for f in args.fields.split(",") if f.strip()]

    seen, all_rows = set(), []
    for q in queries:
        print(f"== 查询: {q}")
        try:
            rows = run_query(q, args.size, args.max_total, fields, channels)
            print(f"    返回 {len(rows)} 行")
        except Exception as e:
            print(f"    失败: {e}")
            continue
        fresh = 0
        for r in rows:
            key = (str(r[0]), str(r[1]))
            if key not in seen:
                seen.add(key)
                all_rows.append(r)
                fresh += 1
        print(f"    去重后新增 {fresh} | 累计 {len(all_rows)}")

    all_rows.sort(key=lambda r: (r[0], r[1]))
    if args.out and all_rows:
        with open(args.out, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(fields)
            w.writerows(all_rows)
        print(f"== CSV 已导出: {args.out} ({len(all_rows)} 行)")
    elif all_rows:
        print(f"== 累计去重 {len(all_rows)} 条(未指定 --out 不落盘), 前 20 条:")
        for r in all_rows[:20]:
            print("    " + " | ".join(str(x) for x in r))
    else:
        print("== 无结果 ==")

if __name__ == "__main__":
    main()
