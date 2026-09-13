#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""结构探查：重取每个 case 原始 body 前 1200 字符，确认真实标签结构 + 提取型号线索。只读 GET。"""
import csv, time, urllib.request, urllib.error, json, re, os

CSV_PATH = "verify_input.csv"
OUT = "probe_bodies.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

def http_get(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            hdrs = dict(r.headers)
            return r.status, hdrs.get("Server",""), r.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Server","") if e.headers else "", ""
    except Exception as e:
        return None, "", str(e)

import argparse
ap = argparse.ArgumentParser(description="结构探查：重取 case 原始 body 头部")
ap.add_argument("--csv", default=CSV_PATH, help="输入 CSV")
ap.add_argument("--out", default=OUT, help="输出 JSON")
_a = ap.parse_args()
CSV_PATH, OUT = _a.csv, _a.out
cases = list(csv.DictReader(open(CSV_PATH, encoding="utf-8-sig")))
out = []
for i, c in enumerate(cases):
    url = c["url"].strip()
    st, srv, body = http_get(url)
    out.append({"case": f"{c['ip']}_{c['port']}_{c['rule_id']}", "status": st, "server": srv,
                "body_head": body[:1200], "body_len": len(body)})
    print(f"[{i+1}/{len(cases)}] {c['ip']} st={st} server={srv!r} len={len(body)}", flush=True)
    time.sleep(1.3)

json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("DONE")
