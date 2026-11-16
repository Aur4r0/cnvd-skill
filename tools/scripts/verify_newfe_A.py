#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""新前端 A 线（密码找回链）独立抽验：
- no_cookie 裸 GET /Security/RecoverPasswordBySuperPassword | RecoverPasswordBySaveQuestion
- real_data: superpw-qr 需 <SuperPasswordQRCode> 双层 base64 解出 p6scloud://superpw/<数字>_<时间戳>
             saveq-open 需 <SaveQuestionList> 密保问题 XML
- 蜜罐三判: ip-api.com geo/isp/as/cloud (间隔>=1.5s)
- device_model 推断
只读 GET；单 IP 间隔 >=1s；绝不兑换。
"""
import csv, json, time, base64, re, urllib.request, urllib.error, socket, datetime, os

CSV_PATH = "verify_input.csv"
OUT_PATH = "verify_report_newfe_A.json"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

def http_get(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(65536).decode("utf-8", errors="replace")
            return r.status, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return None, str(e)

SUPERPW_RE = re.compile(r"<SuperPasswordQRCode>([^<]+)</SuperPasswordQRCode>", re.I)

def check_superpw(body):
    """返回 (real_data_bool, decoded_l2_or_reason, snippet)"""
    m = SUPERPW_RE.search(body)
    if not m:
        # 兼容 SuperPassword 变体标签
        if "<SuperPassword" in body and "QRCode" in body:
            return False, "有SuperPassword标签但无QRCode内容", body[:200]
        return False, "无<SuperPasswordQRCode>标签", ""
    b64 = m.group(1).strip()
    try:
        l1 = base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", errors="replace")
    except Exception as e:
        return False, f"L1 base64 解码失败: {e}", b64[:100]
    if not l1.startswith("p6scloud://superpw/"):
        return False, f"L1 非 p6scloud://superpw/: {l1[:80]}", l1[:120]
    payload = l1.split("superpw/", 1)[1]
    try:
        l2 = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8", errors="replace")
    except Exception as e:
        return False, f"L2 base64 解码失败: {e}", l1[:120]
    m2 = re.match(r"^(\d{6,15})_(\d{9,13})$", l2)
    if not m2:
        return False, f"L2 格式不符 设备ID_时间戳: {l2[:80]}", l1[:120]
    dev_id, ts = m2.groups()
    ts_str = ""
    if 10 <= len(ts) <= 13:
        try:
            t = int(ts)
            if t > 4e12:
                t //= 1000
            ts_str = datetime.datetime.fromtimestamp(
                t, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    snippet = f"L1={l1} | L2={dev_id}_{ts} (UTC {ts_str})"
    return True, {"dev_id": dev_id, "dev_id_len": len(dev_id), "ts": ts, "ts_utc": ts_str}, snippet

SAVEQ_RE = re.compile(r"<SaveQuestionList[\s>]", re.I)
QUESTION_RE = re.compile(r"<Question[^>]*>([^<]{1,200})</Question>", re.I)

def check_saveq(body):
    """返回 (real_data_bool, detail, snippet)"""
    if SAVEQ_RE.search(body):
        qs = QUESTION_RE.findall(body)
        detail = {"question_count": len(qs), "questions": [q.strip() for q in qs[:5]]}
        ok = len(qs) >= 1
        return ok, detail, ("; ".join(q.strip() for q in qs[:3]))[:200]
    # 宽容：有密保语义但结构不同
    if re.search(r"(savequestion|securityquestion|密保)", body, re.I):
        return False, "含 savequestion 关键词但无 SaveQuestionList 结构", body[:150]
    return False, "无<SaveQuestionList>标签", ""

CLOUD_KWS = ["cloud","amazon","aws","azure","google","digitalocean","alibaba","aliyun",
             "tencent","huawei cloud","vultr","linode","ovh","oracle","hosting","host",
             "data center","datacenter","rackspace","scaleway","leaseweb","contabo",
             "hetzner","choopa","colocation","colo cross","server","idc"]

def geo(ip):
    url = f"http://ip-api.com/json/{ip}?fields=query,status,country,countryCode,isp,org,as,mobile,proxy,hosting"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8"))
        return d
    except Exception as e:
        return {"error": str(e)}

MODEL_SIGS = [
    ("YLT", ["ylt"]),
    ("P6S/云视通", ["p6s", "yunshitong", "cloudsee"]),
    ("HiWatch/Hikvision", ["hikvision", "hiwatch", "davinci"]),
    ("Dahua", ["dahua"]),
    ("XiongMai", ["xmeye", "net_surveillance"]),
    ("Uniview", ["uniview", "unv"]),
]

def infer_model(headers_text, body, ip):
    blob = (headers_text + " " + body[:4000]).lower()
    for name, kws in MODEL_SIGS:
        for kw in kws:
            if kw in blob:
                return name
    return "unknown"

def main():
    import argparse
    ap = argparse.ArgumentParser(description="新前端A线(密码找回链)独立抽验")
    ap.add_argument("--csv", default=CSV_PATH, help="输入 CSV(表头含 ip,port,rule_id,url)")
    ap.add_argument("--out", default=OUT_PATH, help="输出 JSON 报告")
    a = ap.parse_args()
    globals()["CSV_PATH"], globals()["OUT_PATH"] = a.csv, a.out
    with open(CSV_PATH, encoding="utf-8-sig") as f:
        cases = list(csv.DictReader(f))
    n = len(cases)
    print(f"total cases: {n}")
    results = []
    last_ip = None
    for i, c in enumerate(cases):
        # CSV 空字段读出来是 None, 不是 "" —— 直接 .strip() 会 AttributeError
        ip = (c.get("ip") or "").strip()
        port = (c.get("port") or "").strip()
        rule = (c.get("rule_id") or "").strip()
        url = (c.get("url") or "").strip()
        if not url or not ip:
            print(f"[{i+1}/{n}] 跳过: url/ip 为空", flush=True)
            continue
        case_id = f"{ip}_{port}_{rule}"
        print(f"[{i+1}/{n}] {case_id} ...", flush=True)

        if last_ip is not None and ip != last_ip:
            time.sleep(1.2)          # 单 IP 间隔
        st, body = http_get(url)

        rec = {
            "case_id": case_id,
            "verdict": "",
            "checks": {"no_cookie_repro": False, "real_data": False,
                       "honeypot": {"suspect": False, "reason": ""},
                       "device_model": "", "geo": {"isp": "", "as": "", "cloud": "no"}},
            "evidence": {"snippet": ""},
            "fail_reason": ""
        }

        repro_ok = (st == 200)
        real_ok = False
        extra = {}
        if repro_ok:
            if rule == "superpw-qr":
                real_ok, extra, snip = check_superpw(body)
            elif rule == "saveq-open":
                real_ok, extra, snip = check_saveq(body)
            else:
                real_ok, extra, snip = False, f"未知rule_id {rule}", ""
            rec["checks"]["no_cookie_repro"] = True
            rec["checks"]["real_data"] = bool(real_ok)
            rec["evidence"]["snippet"] = (snip or "")[:200]
        else:
            rec["fail_reason"] = f"HTTP {st}: {str(body)[:120]}"

        # geo 查询（每 case 一次，与上次查询天然间隔因请求耗时+显式 sleep）
        g = geo(ip)
        isp = g.get("isp", "") or ""
        org = g.get("org", "") or ""
        asn = g.get("as", "") or ""
        cloud_flag = "yes" if g.get("hosting") else "no"
        low = (isp + " " + org + " " + asn).lower()
        kw_hit = next((k for k in CLOUD_KWS if k in low), "")
        suspect = (cloud_flag == "yes") or bool(kw_hit)
        reason = []
        if g.get("hosting"):
            reason.append("ip-api hosting=true")
        if g.get("proxy"):
            reason.append("ip-api proxy=true")
        if kw_hit:
            reason.append(f"ISP/AS 含关键词 '{kw_hit}'")
        if g.get("error"):
            reason.append(f"geo查询失败:{g['error']}")
        rec["checks"]["honeypot"] = {"suspect": suspect, "reason": "; ".join(reason)}
        rec["checks"]["geo"] = {"isp": f"{isp} / {org}".strip(" /"), "as": asn,
                                "cloud": cloud_flag}
        rec["checks"]["country"] = g.get("countryCode", "")

        if repro_ok:
            # http_get 不取响应头, headers_text 传空, 型号只能从 body 推断
            rec["checks"]["device_model"] = infer_model("", body, ip)

        # verdict
        if not repro_ok:
            rec["verdict"] = "excluded" if st in (401, 403, 404, 405, None) or st is None else "needs_review"
            if st is None or st == "timeout":
                rec["verdict"] = "excluded"
                rec["fail_reason"] = rec["fail_reason"] or "连接失败/超时"
        elif real_ok:
            rec["verdict"] = "confirmed" if not suspect else "needs_review"
            if suspect and isinstance(extra, dict):
                rec["fail_reason"] = f"数据自洽但归属存疑: {rec['checks']['honeypot']['reason']}"
        else:
            rec["verdict"] = "needs_review"
            rec["fail_reason"] = f"复现200但数据不合规: {extra}"

        if real_ok and isinstance(extra, dict):
            rec["decoded"] = extra   # 仅记录格式，绝不兑换
        results.append(rec)

        time.sleep(max(1.0, 1.6 - (time.time() % 1)))  # ip-api 间隔>=1.5s 近似
        with open(OUT_PATH, "w", encoding="utf-8") as fo:
            json.dump(results, fo, ensure_ascii=False, indent=2)
        print(f"    -> {rec['verdict']} cloud={cloud_flag} real={real_ok}", flush=True)
        last_ip = ip

    # summary
    summary = {"total": n,
               "confirmed": sum(1 for r in results if r["verdict"] == "confirmed"),
               "excluded": sum(1 for r in results if r["verdict"] == "excluded"),
               "needs_review": sum(1 for r in results if r["verdict"] == "needs_review")}
    final = {"cases": results, "summary": summary}
    with open(OUT_PATH, "w", encoding="utf-8") as fo:
        json.dump(final, fo, ensure_ascii=False, indent=2)
    print("DONE", OUT_PATH)
    print(json.dumps(summary))

if __name__ == "__main__":
    main()
