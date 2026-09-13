#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CNVD 阶段1 定级检测 —— 未授权能力点批量验证(只读)
并发模型: 跨 IP 并发(线程池), 单 IP 严格串行(间隔≥1s)。
差分验证: HTTP 命中做第二次无 cookie 请求, 不可复现 → 丢弃。
蜜罐排除: --geo 开启 ip-api 归属查询, 云厂商段标 cloud_suspect=yes。
协议面: HTTP(GET) + RTSP(OPTIONS/DESCRIBE) + FTP(anonymous LIST)。
用法:
  python cnvd_check.py --targets 资产.csv --rules rules.json [--geo]
                       [--interval 1.0] [--workers 10] [--timeout 8] [--out findings.csv]
"""
import argparse, csv, ftplib, json, os, socket, ssl, sys, threading, time
import urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

CLOUD_WORDS = ["alibaba", "aliyun", "tencent", "huawei", "amazon", "aws", "microsoft",
               "azure", "google", "cloud", "ovh", "digitalocean", "vultr", "ucloud",
               "qingcloud", "baidu", "lightnode"]
RTSP_STREAMS = ["/", "/live", "/stream1", "/ch1/main",
                "/cam/realmonitor?channel=1&subtype=0", "/1"]
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def load_targets(path):
    with open(path, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    targets = []
    for r in rows:
        try:
            targets.append({"ip": r["ip"].strip(), "port": int(r["port"])})
        except (KeyError, ValueError):
            continue
    return targets


def load_rules(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("rules", [])


class Pacer:
    """跨 IP 并发, 单 IP 串行且间隔 >= interval 秒"""
    def __init__(self, interval):
        self.interval = interval
        self._g = threading.Lock()
        self._locks = {}
        self._last = {}

    def acquire(self, ip):
        with self._g:
            lock = self._locks.setdefault(ip, threading.Lock())
        lock.acquire()
        with self._g:
            wait = self.interval - (time.time() - self._last.get(ip, 0))
        if wait > 0:
            time.sleep(wait)
        with self._g:
            self._last[ip] = time.time()
        return lock

    def release(self, ip, lock):
        lock.release()


def http_get(url, timeout, method=None, body=None, ctype=None):
    headers = {"User-Agent": "Mozilla/5.0 (cnvd-check)"}
    if ctype:
        headers["Content-Type"] = ctype
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, headers=headers, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
            b = resp.read().decode("utf-8", "replace")
            return resp.status, b
    except Exception:
        return None


def extract_snippet(body, hits):
    if not hits:
        return " ".join(body[:200].split())[:200]
    i = body.lower().find(hits[0])
    if i < 0:
        return " ".join(body[:200].split())[:200]
    return " ".join(body[max(0, i - 120):i + 120].split())[:300]


def evaluate_http(status, body, rule):
    if status >= 400:
        return None
    b = body.lower()
    for x in rule.get("exclude_any", []):
        if x.lower() in b:
            return None
    if len(body) < rule.get("min_len", 0):
        return None
    mock = any(x.lower() in b for x in rule.get("fake_hints", []))
    matches = [x.lower() for x in rule.get("match_any", [])]
    hits = [m for m in matches if m in b]
    if matches and not hits:
        return None
    return {"hits": hits, "mock": mock, "snippet": extract_snippet(body, hits),
            "needs_review": not matches}


def http_probe(ip, port, rule, timeout, pacer):
    out = []
    scheme = "https" if port in (443, 8443) else "http"
    method = rule.get("method", "GET")
    body = rule.get("body")
    ctype = rule.get("content_type")
    for path in rule.get("paths", []):
        url = f"{scheme}://{ip}:{port}{urllib.parse.quote(path, safe='/%?=&:')}"
        lock = pacer.acquire(ip)
        try:
            r = http_get(url, timeout, method, body, ctype)
        finally:
            pacer.release(ip, lock)
        if not r:
            continue
        v = evaluate_http(*r, rule)
        if not v:
            continue
        time.sleep(pacer.interval)          # 复现请求间隔
        lock = pacer.acquire(ip)
        try:
            r2 = http_get(url, timeout, method, body, ctype)
        finally:
            pacer.release(ip, lock)
        if r2 and evaluate_http(*r2, rule):
            out.append({"type": "http", "url": url, **v})
    return out


def recv_all(s):
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data and len(data) > 200:
                break
    except OSError:
        pass
    return data.decode("utf-8", "replace")


def rtsp_probe(ip, port, timeout):
    """v2 严格判据: DESCRIBE 200 且响应含 SDP(v=0 + m=video/audio) 才命中;
    OPTIONS-only / DESCRIBE 无 SDP 一律丢弃(防误报噪音, 08-22 实战教训)"""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        if "RTSP/1.0 200" not in recv_all(s):
            s.close()
            return []
        described = None
        for path in RTSP_STREAMS:
            s.sendall(f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\nCSeq: 2\r\n"
                      f"Accept: application/sdp\r\n\r\n".encode())
            resp = recv_all(s)
            if "RTSP/1.0 200" in resp and "v=0" in resp and \
               ("m=video" in resp or "m=audio" in resp):
                described = path
                break
        s.close()
        if described is not None:
            return [{"type": "rtsp", "url": f"rtsp://{ip}:{port}{described}",
                     "hits": ["rtsp200"], "mock": False, "needs_review": False,
                     "snippet": "OPTIONS+DESCRIBE 200 且 SDP 含视频/音频流 → 未授权可拉流"}]
        return []   # OPTIONS-only 或无 SDP = 丢弃, 不产出噪音
    except OSError:
        return []


def ftp_probe(ip, port, timeout):
    try:
        f = ftplib.FTP()
        f.connect(ip, port, timeout=timeout)
        f.set_pasv(True)
        resp = f.login("anonymous", "anonymous@example.com")
        if not resp.startswith("230"):
            f.close()
            return []
        try:
            names = f.nlst()[:10]
        except Exception:
            names = ["<列表获取失败>"]
        try:
            f.quit()
        except Exception:
            f.close()
        return [{"type": "ftp", "url": f"ftp://{ip}:{port}/",
                 "hits": ["anonymous230"], "mock": False, "needs_review": False,
                 "snippet": "anonymous 230, 目录: " + ", ".join(names)}]
    except Exception:
        return []


def geo_lookup(ip, cache, lock):
    with lock:
        if ip in cache:
            return cache[ip]
    url = f"http://ip-api.com/json/{ip}?fields=query,country,regionName,city,isp,org,as"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cnvd-check"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            d = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        d = {"query": ip, "isp": "?", "org": "?", "as": "?"}
    time.sleep(1.2)  # 免费档 45 次/分
    with lock:
        cache[ip] = d
    return d


def is_cloud(d):
    blob = f"{d.get('isp', '')} {d.get('org', '')}".lower()
    return any(w in blob for w in CLOUD_WORDS)


def main():
    p = argparse.ArgumentParser(description="CNVD 未授权定级检测(只读)")
    p.add_argument("--targets", required=True, help="资产 CSV(表头含 ip,port)")
    p.add_argument("--rules", required=True, help="规则 JSON")
    p.add_argument("--interval", type=float, default=1.0, help="同 IP 请求间隔秒(默认1)")
    p.add_argument("--workers", type=int, default=10, help="跨 IP 并发数")
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--geo", action="store_true", help="ip-api 归属查询+云厂商标记(慢)")
    p.add_argument("--out", default="findings.csv")
    p.add_argument("--resume", action="store_true", help="断点续跑：读已有 --out 文件，跳过已完成的 ip:port")
    args = p.parse_args()

    targets = load_targets(args.targets)
    rules = load_rules(args.rules)

    done_keys = set()
    old_findings = []
    if args.resume and os.path.isfile(args.out):
        with open(args.out, encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                old_findings.append(row)
                done_keys.add((row.get("ip", ""), row.get("port", "")))
        targets = [t for t in targets if (t["ip"], str(t["port"])) not in done_keys]
        print(f"== 断点续跑: 已有 {len(old_findings)} 条 findings, 剩余 {len(targets)} 个待扫 ==")

    print(f"== 目标 {len(targets)} 个 | 规则 {len(rules)} 条 | "
          f"间隔 {args.interval}s | 并发 {args.workers} ==")

    pacer = Pacer(args.interval)
    findings, fl = [], threading.Lock()
    geo_cache, geo_lock = {}, threading.Lock()
    done = [0]

    def work(t):
        ip, port = t["ip"], t["port"]
        res = []
        for rule in rules:
            rtype = rule.get("type", "http")
            if rtype == "http":
                items = http_probe(ip, port, rule, args.timeout, pacer)
            elif rtype == "rtsp":
                items = rtsp_probe(ip, rule.get("port", 554), args.timeout)
            elif rtype == "ftp":
                items = ftp_probe(ip, rule.get("port", 21), args.timeout)
            else:
                items = []
            for it in items:
                it.update({"ip": ip, "port": port, "rule_id": rule.get("id", "?"),
                           "rule_name": rule.get("name", "?"),
                           "severity": rule.get("severity", "review"),
                           "note": rule.get("note", "")})
            res.extend(items)
        if args.geo:
            d = geo_lookup(ip, geo_cache, geo_lock)
            for it in res:
                it["isp"] = d.get("isp", "")
                it["org"] = d.get("org", "")
                it["as"] = d.get("as", "")
                it["cloud_suspect"] = "yes" if is_cloud(d) else "no"
        with fl:
            findings.extend(res)
            done[0] += 1
            print(f"    完成 {done[0]}/{len(targets)} {ip}:{port} 命中 {len(res)}", flush=True)
        return res

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        ex.map(work, targets)

    all_findings = old_findings + findings
    all_findings.sort(key=lambda f: ({"high": 0, "mid": 1, "low": 2,
                                  "review": 3}.get(f.get("severity", "review"), 9), f.get("ip", "")))
    cols = ["ip", "port", "rule_id", "rule_name", "severity", "type", "url",
            "hits", "mock", "needs_review", "cloud_suspect", "isp", "org", "as",
            "snippet", "note"]
    with open(args.out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in all_findings:
            row = {k: r.get(k, "") for k in cols}
            if isinstance(row.get("hits", ""), list):
                row["hits"] = ",".join(row["hits"])
            w.writerow(row)
    print(f"== findings 已导出 {args.out} ({len(all_findings)} 条, 含旧 {len(old_findings)}) ==")
    print("    定级分布:", dict(Counter(f.get("severity", "review") for f in all_findings)))


if __name__ == "__main__":
    main()
