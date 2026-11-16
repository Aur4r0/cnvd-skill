#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RTSP 批量补验：OPTIONS + DESCRIBE 裸连 + ip-api 归属。只读，不发 SETUP/PLAY。"""
import socket, csv, json, time, urllib.request, sys, os

CSV_PATH = "verify_input.csv"
OUT_PATH = "verify_report_rtsp2.json"

STD_PATHS = ["/", "/live", "/stream1", "/ch1/main",
             "/cam/realmonitor?channel=1&subtype=0", "/1"]
VAR_PATHS = ["/stream2", "/ch1/sub", "/main", "/Channel1",
             "/live/ch0", "/profile1", "/h264"]

def sock_send(ip, port, payload, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(payload)
        data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                # RTSP responses end by Content-Length or CRLFCRLF; for DESCRIBE may be multi-chunk
                if b"\r\n\r\n" in data and data.count(b"\r\n\r\n") >= 1:
                    # attempt to read a bit more for SDP
                    try:
                        s.settimeout(1.0)
                        more = s.recv(8192)
                        if more:
                            data += more
                    except socket.timeout:
                        pass
                    break
            except socket.timeout:
                break
        return data
    except Exception as e:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

def has_sdp(resp):
    """与 cnvd_check.py 的 rtsp_probe 保持同一判据: 必须 v=0 + m=video/audio。
    不接受 m=video+a=control 的宽松分支 —— 那种响应可能是错误页/非 SDP 内容,
    宽松判据会让抽验 confirm 主扫描不认的命中, 两套判据必须一致。"""
    if not resp:
        return False
    t = resp.decode("utf-8", errors="ignore")
    return "v=0" in t and ("m=video" in t or "m=audio" in t)

def check_one(ip, port, url_base):
    """Returns (best_status, sdp_snippet, summary)."""
    best = {"code": None, "sdp": False, "snippet": "", "status": ""}
    # OPTIONS
    opts_req = (f"OPTIONS {url_base.rstrip('/')} RTSP/1.0\r\nCSeq: 1\r\n"
                f"User-Agent: LibVLC/3.0.16 (LIVE555 Streaming Media v2016.11.28)\r\n\r\n").encode()
    opt_resp = sock_send(ip, port, opts_req)
    opts_status = ""
    if opt_resp:
        first = opt_resp.split(b"\r\n")[0].decode("utf-8", errors="ignore")
        opts_status = first
        best["status"] = first

    all_paths = STD_PATHS + VAR_PATHS
    cseq = 2
    for path in all_paths:
        u = url_base.rstrip("/") + path if not path.startswith("/") else (url_base.rstrip("/") + path)
        desc_req = (f"DESCRIBE {u} RTSP/1.0\r\nCSeq: {cseq}\r\n"
                    f"Accept: application/sdp\r\n"
                    f"User-Agent: LibVLC/3.0.16 (LIVE555 Streaming Media v2016.11.28)\r\n\r\n").encode()
        cseq += 1
        resp = sock_send(ip, port, desc_req)
        if resp:
            first = resp.split(b"\r\n")[0].decode("utf-8", errors="ignore")
            code = first.split()[1] if len(first.split()) > 1 else ""
            if code == "200":
                if has_sdp(resp):
                    t = resp.decode("utf-8", errors="ignore")
                    snip = t[:600]
                    best = {"code": 200, "sdp": True, "snippet": snip,
                            "status": first, "path": path}
                    return best
                else:
                    if best["code"] is None:
                        best = {"code": 200, "sdp": False,
                                "snippet": resp.decode("utf-8", errors="ignore")[:400],
                                "status": first, "path": path}
            elif best["code"] is None:
                best = {"code": code, "sdp": False,
                        "snippet": resp.decode("utf-8", errors="ignore")[:300],
                        "status": first, "path": path}
        time.sleep(1.0)  # single IP interval >= 1s
    return best

def geo(ip):
    url = f"http://ip-api.com/json/{ip}?fields=query,isp,org,as,country"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8"))
        return d
    except Exception as e:
        return {"error": str(e)}

def infer_model(sdp, ip):
    t = (sdp or "").lower()
    if "hikvision" in t or "davinci" in t:
        return "Hikvision"
    if "dahua" in t:
        return "Dahua"
    if "axis" in t:
        return "Axis"
    if "vivotek" in t:
        return "Vivotek"
    if "server: gstreamer" in t:
        return "GStreamer"
    if "x-nt" in t:
        return "Sony/Tamron"
    return "unknown"

def main():
    import argparse
    ap = argparse.ArgumentParser(description="RTSP 批量补验(OPTIONS+DESCRIBE 裸连)")
    ap.add_argument("--csv", default=CSV_PATH, help="输入 CSV")
    ap.add_argument("--out", default=OUT_PATH, help="输出 JSON 报告")
    a = ap.parse_args()
    globals()["CSV_PATH"], globals()["OUT_PATH"] = a.csv, a.out
    cases = []
    with open(CSV_PATH, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            cases.append(row)

    results = []
    n = len(cases)
    print(f"total cases: {n}")
    for i, c in enumerate(cases):
        ip = c["ip"].strip()
        # url gives port/path; strip scheme
        url = c["url"].strip()
        # parse port from url
        rest = url.split("://", 1)[1]
        hostport, _, path = rest.partition("/")
        if ":" in hostport:
            host, port = hostport.rsplit(":", 1)
            port = int(port)
        else:
            host, port = hostport, 554
        # host in url may differ from ip column; trust ip column for connect, url for path
        port_from_url = port
        port = int(c["port"].strip()) if c["port"].strip() else 554
        # Actually url has the real RTSP port (554), port column is 80 (weird). Use url port.
        port = port_from_url

        url_base = f"rtsp://{ip}:{port}"
        print(f"[{i+1}/{n}] {ip}:{port} ...", flush=True)

        best = check_one(ip, port, url_base)

        g = geo(ip)
        isp = g.get("isp", "") or ""
        org = g.get("org", "") or ""
        asn = g.get("as", "") or ""
        cloud = "no"
        cloud_reason = ""
        # cloud detection keywords
        low = (isp + " " + org + " " + asn).lower()
        for kw in ["cloud", "amazon", "aws", "azure", "google", "digitalocean",
                   "alibaba", "aliyun", "tencent", "huawei cloud", "vultr",
                   "linode", "ovh", "oracle", "hosting", "host", "data center",
                   "datacenter", "rackspace", "scaleway", "leaseweb"]:
            if kw in low:
                cloud = "yes"
                cloud_reason = kw
                break

        if best.get("sdp"):
            verdict = "confirmed"
            no_cookie_repro = True
            device_model = infer_model(best.get("snippet", ""), ip)
            fail_reason = ""
        else:
            no_cookie_repro = False
            if best.get("code") == 200:
                verdict = "needs_review"
                fail_reason = f"DESCRIBE 200 但无 SDP（{best.get('path','')}）: {best.get('snippet','')[:120]}"
            elif best.get("code") in ("401", "403", "404", "405"):
                verdict = "excluded"
                fail_reason = f"DESCRIBE 返回 {best.get('code')}（{best.get('status','')[:80]}）"
            elif best.get("code") is None and best.get("status"):
                verdict = "needs_review"
                fail_reason = f"DESCRIBE 无明确 200: {best.get('status','')[:100]}"
            else:
                verdict = "needs_review"
                fail_reason = f"连接/响应异常: {best.get('status','') or 'timeout/refused'}"
            device_model = infer_model(best.get("snippet", ""), ip)

            # distinguish excluded: refused/timeout = excluded (not reachable)
            if best.get("code") is None and not best.get("status"):
                verdict = "excluded"
                fail_reason = "连接失败/timeout/refused（端口未开放或不复现）"

        results.append({
            "case_id": c["case_id"].strip(),
            "verdict": verdict,
            "checks": {
                "no_cookie_repro": no_cookie_repro,
                "real_data": (best.get("snippet", "")[:400] if best.get("sdp") else ""),
                "honeypot": cloud,
                "honeypot_reason": cloud_reason,
                "device_model": device_model,
                "geo": {"isp": isp, "as": asn, "cloud": cloud}
            },
            "evidence": {"sdp_snippet": best.get("snippet", "")[:600]},
            "fail_reason": fail_reason
        })

        time.sleep(1.5)  # ip-api interval >=1.5s
        # write incrementally so progress persists
        with open(OUT_PATH, "w", encoding="utf-8") as fo:
            json.dump(results, fo, ensure_ascii=False, indent=2)
        print(f"    -> {verdict} cloud={cloud}", flush=True)

    print("DONE, written", OUT_PATH)

if __name__ == "__main__":
    main()
