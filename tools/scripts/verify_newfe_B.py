#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""newfe B 线独立抽验 v2.0 §1.3：
- config-uid:   GET /Config.json 判据=拿到 P2P UID/序列号等设备唯一标识；空壳/404=excluded
- onvif-info:   POST GetDeviceInformation 判据=四元组 Manufacturer/Model/FirmwareVersion/SerialNumber 全非空；空/错=excluded
- rtsp-unauth:  仅 OPTIONS+DESCRIBE；DESCRIBE 200 且 SDP(v=0 且 m=video/audio)=confirmed；仅 OPTIONS 200=excluded
红线：只读；无 SETUP/PLAY；单 IP 间隔>=1s；geo(ip-api) 间隔>=1.5s。
"""
import socket, csv, json, time, re, sys, os
import urllib.request, urllib.error

CSV_PATH = "verify_input.csv"
OUT_PATH = "verify_report_newfe_B.json"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

_last_http_time = [0.0]
_geo_last = [0.0]

# ---------- low level ----------
def http_req(ip, port, path, method="GET", body=None, headers=None, timeout=8):
    gap = time.time() - _last_http_time[0]
    if gap < 1.0:
        time.sleep(1.0 - gap)
    _last_http_time[0] = time.time()
    try:
        url = f"http://{ip}:{port}{path}"
        h = {"User-Agent": UA, "Accept": "*/*"}
        if headers:
            h.update(headers)
        data = body.encode("utf-8") if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(131072)
            return r.status, dict(r.headers), raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            txt = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            txt = ""
        return e.code, dict(e.headers), txt
    except Exception as ex:
        return None, {}, type(ex).__name__ + ": " + str(ex)[:120]

def sock_send(ip, port, payload, timeout=6):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(payload)
        data = b""
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    try:
                        s.settimeout(1.2)
                        more = s.recv(32768)
                        if more:
                            data += more
                    except socket.timeout:
                        pass
                    break
            except socket.timeout:
                break
        return data
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

def rtsp_gap():
    gap = time.time() - _last_http_time[0]
    if gap < 1.0:
        time.sleep(1.0 - gap)
    _last_http_time[0] = time.time()

def geo_lookup(ip):
    gap = time.time() - _geo_last[0]
    if gap < 1.6:
        time.sleep(1.6 - gap)
    _geo_last[0] = time.time()
    url = f"http://ip-api.com/json/{ip}?fields=query,isp,org,as,country,hosting"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=12) as r:
            d = json.loads(r.read().decode("utf-8"))
        return d
    except Exception as ex:
        return {"error": type(ex).__name__}

CLOUD_KW = ["cloud", "amazon", "aws", "azure", "google", "digitalocean", "alibaba",
            "aliyun", "tencent", "huawei cloud", "vultr", "linode", "ovh", "oracle",
            "hosting", "data center", "datacenter", "rackspace", "scaleway", "leaseweb",
            "hetzner", "contabo", "choopa"]

def honeypot_check(g):
    isp = g.get("isp", "") or ""
    org = g.get("org", "") or ""
    asn = g.get("as", "") or ""
    hosting = bool(g.get("hosting", False))
    blob = (isp + " " + org + " " + asn).lower()
    kw_hit = next((k for k in CLOUD_KW if k in blob), "")
    suspect = hosting or bool(kw_hit)
    reason = []
    if hosting:
        reason.append("ip-api hosting=true")
    if kw_hit:
        reason.append(f"keyword:{kw_hit}")
    return suspect, "; ".join(reason)

# ---------- rule checks ----------
UID_RE = re.compile(r"\b([A-Z]{3,8}-\d{3,9}-[A-Z0-9]{3,8}|YLT[A-Za-z0-9]{6,})\b")

def check_config_uid(ip, port):
    st, hd, body = http_req(ip, port, "/Config.json")
    if st is None:
        st2, hd2, body2 = http_req(ip, port, "/Config.json")
        if st2 is None:
            return "excluded", False, "", f"unreachable ({body[:80]})", ""
        st, hd, body = st2, hd2, body2
    if st != 200:
        return "excluded", True, body[:150], f"HTTP {st}", body[:180]
    b = body.strip()
    # empty shell: no UID-like token, no meaningful keys
    uid_m = UID_RE.search(b)
    has_keys = any(k.lower() in b.lower() for k in ["uid", "deviceid", "serialnumber", "p2p"])
    if uid_m:
        snip = b[max(0, uid_m.start() - 60): uid_m.end() + 60].replace("\n", " ")
        return "confirmed", True, snip[:200], "", body[:180]
    if has_keys and len(b) > 40 and "<html" not in b[:400].lower():
        # keys exist but no recognizable value -> review
        return "needs_review", True, b.replace("\n", " ")[:200], "keys but no UID-pattern value", body[:180]
    return "excluded", True, b[:150], "empty shell / no device identifier", body[:180]

SOAP_GETDEVINFO = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
    '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
    '</s:Body></s:Envelope>')

def tag_val(xml, tag):
    m = re.search(rf"<(?:[\w.-]+:)?{tag}>(.*?)</(?:[\w.-]+:)?{tag}>", xml, re.S)
    return m.group(1).strip() if m else ""

def check_onvif(ip, port):
    hdrs = {"Content-Type": 'application/soap+xml; charset=utf-8',
            "SOAPAction": '"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"'}
    st, hd, body = http_req(ip, port, "/onvif/device_service", method="POST",
                            body=SOAP_GETDEVINFO, headers=hdrs, timeout=10)
    if st is None:
        st, hd, body = http_req(ip, port, "/onvif/device_service", method="POST",
                                body=SOAP_GETDEVINFO, headers=hdrs, timeout=10)
        if st is None:
            return "excluded", False, "", f"unreachable ({body[:80]})", ""
    if st != 200:
        return "excluded", True, body[:120], f"HTTP {st}", body[:180]
    vals = {t: tag_val(body, t) for t in
            ["Manufacturer", "Model", "FirmwareVersion", "SerialNumber"]}
    got = [k for k, v in vals.items() if v]
    if len(got) == 4:
        quad = " | ".join(f"{k}={vals[k]}" for k in vals)
        return "confirmed", True, quad[:200], "", body[:180]
    if got:
        miss = ",".join(k for k in vals if not vals[k])
        partial = " | ".join(f"{k}={vals[k]}" for k in vals if vals[k])
        return "needs_review", True, partial[:200], f"partial quad, missing: {miss}", body[:180]
    if "<html" in body[:300].lower() or len(body.strip()) < 30:
        return "excluded", True, body[:120], "empty/non-SOAP response", body[:180]
    return "excluded", True, body[:120], "no device info fields in response", body[:180]

RTSP_PATHS = ["/", "/live", "/stream1", "/ch1/main",
              "/cam/realmonitor?channel=1&subtype=0"]

def check_rtsp(ip, port):
    base = f"rtsp://{ip}:{port}"
    rtsp_gap()          # OPTIONS 是一个独立请求, 同样要受单 IP 间隔约束
    opt = sock_send(ip, port,
                    f"OPTIONS {base} RTSP/1.0\r\nCSeq: 1\r\n"
                    f"User-Agent: LibVLC/3.0.16\r\n\r\n".encode())
    opts_status = opt.split(b"\r\n")[0].decode("utf-8", "ignore") if opt else ""
    if not opt:
        time.sleep(2.0)
        rtsp_gap()
        opt = sock_send(ip, port,
                        f"OPTIONS {base} RTSP/1.0\r\nCSeq: 1\r\n"
                        f"User-Agent: LibVLC/3.0.16\r\n\r\n".encode(), timeout=8)
        opts_status = opt.split(b"\r\n")[0].decode("utf-8", "ignore") if opt else ""
        if not opt:
            return "excluded", False, "", f"unreachable ({opts_status or 'timeout/refused'})", ""
    cseq = 2
    best_code, best_snip = "", ""
    for p in RTSP_PATHS:
        rtsp_gap()
        u = base + p
        resp = sock_send(ip, port,
                         f"DESCRIBE {u} RTSP/1.0\r\nCSeq: {cseq}\r\n"
                         f"Accept: application/sdp\r\n"
                         f"User-Agent: LibVLC/3.0.16\r\n\r\n".encode())
        cseq += 1
        if not resp:
            continue
        first = resp.split(b"\r\n")[0].decode("utf-8", "ignore")
        parts = first.split()
        code = parts[1] if len(parts) > 1 else ""
        t = resp.decode("utf-8", "ignore")
        if code == "200":
            if "v=0" in t and ("m=video" in t or "m=audio" in t):
                snip = t[t.find("\r\n\r\n") + 4:] if "\r\n\r\n" in t else t
                return "confirmed", True, snip[:200], "", t[:250]
            if not best_code:
                best_code, best_snip = "200-noSDP", t[:200]
        elif not best_code:
            best_code, best_snip = code or "?", t[:150]
    if best_code == "200-noSDP":
        return "needs_review", True, best_snip, "DESCRIBE 200 but no SDP", best_snip
    if best_code.startswith(("401", "403", "404", "405")):
        return "excluded", True, best_snip, f"auth/absent: DESCRIBE {best_code}", best_snip
    # OPTIONS 200 but no usable DESCRIBE result -> per spec excluded
    fail = f"only OPTIONS ({opts_status[:40]}); DESCRIBE: {best_code or 'no response'}"
    return "excluded", True, (best_snip or opts_status)[:200], fail, best_snip[:180]

# ---------- main ----------
def main():
    import argparse
    ap = argparse.ArgumentParser(description="新前端B线(泄露面)独立抽验")
    ap.add_argument("--csv", default=CSV_PATH, help="输入 CSV")
    ap.add_argument("--out", default=OUT_PATH, help="输出 JSON 报告")
    a = ap.parse_args()
    globals()["CSV_PATH"], globals()["OUT_PATH"] = a.csv, a.out
    cases = []
    with open(CSV_PATH, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row.get("ip"):
                cases.append(row)
    out = []
    n = len(cases)
    print(f"total: {n}")
    for i, c in enumerate(cases):
        # CSV 空字段读出来是 None, 不是 "" —— 直接 .strip() 会 AttributeError
        ip = (c.get("ip") or "").strip()
        rule = (c.get("rule_id") or "").strip()
        port_col = (c.get("port") or "").strip()
        url = (c.get("url") or "").strip()
        if not url or not ip:
            print(f"[{i+1}/{n}] 跳过: url/ip 为空", flush=True)
            continue
        case_id = f"{ip}_{port_col}_{rule}"
        print(f"[{i+1}/{n}] {case_id} ...", flush=True)

        if rule == "rtsp-unauth":
            rest = url.split("://", 1)[1]
            hostport = rest.partition("/")[0]
            rport = int(hostport.rsplit(":", 1)[1]) if ":" in hostport else 554
            verdict, real, snip, fail, ev = check_rtsp(ip, rport)
        elif rule == "config-uid":
            verdict, real, snip, fail, ev = check_config_uid(ip, int(port_col))
        elif rule == "onvif-info":
            verdict, real, snip, fail, ev = check_onvif(ip, int(port_col))
        else:
            verdict, real, snip, fail, ev = "needs_review", False, "", f"unknown rule {rule}", ""

        g = geo_lookup(ip)
        sus, sus_reason = honeypot_check(g)
        out.append({
            "case_id": case_id,
            "verdict": verdict,
            "checks": {
                "no_cookie_repro": verdict == "confirmed",
                "real_data": bool(real),
                "honeypot": {"suspect": sus, "reason": sus_reason},
                "geo": {"isp": g.get("isp", ""), "as": g.get("as", ""),
                        "cloud": "yes" if sus else "no"}
            },
            "evidence": {"snippet": (snip or "")[:200]},
            "fail_reason": fail,
            "_raw_probe": (ev or "")[:180],
        })
    summary = {"total": n,
               "confirmed": sum(1 for x in out if x["verdict"] == "confirmed"),
               "excluded": sum(1 for x in out if x["verdict"] == "excluded"),
               "needs_review": sum(1 for x in out if x["verdict"] == "needs_review")}
    report = {"cases": out, "summary": summary}
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print("summary:", json.dumps(summary))
    for x in out:
        print(f"{x['case_id']}: {x['verdict']}  {x['fail_reason'][:60]}")

if __name__ == "__main__":
    main()
