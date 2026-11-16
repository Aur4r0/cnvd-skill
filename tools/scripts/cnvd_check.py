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
import argparse, csv, ftplib, ipaddress, json, os, re, socket, ssl, sys, threading, time
import urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from contextlib import contextmanager
from datetime import datetime

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

CLOUD_WORDS = ["alibaba", "aliyun", "tencent", "huawei", "amazon", "aws", "microsoft",
               "azure", "google", "cloud", "ovh", "digitalocean", "vultr", "ucloud",
               "qingcloud", "baidu", "lightnode"]
RTSP_STREAMS = ["/", "/live", "/stream1", "/ch1/main",
                "/cam/realmonitor?channel=1&subtype=0", "/1"]
# 目标端口若属于这些常见 Web 端口，说明该行为 HTTP 资产，不再用同端口探 RTSP/FTP
COMMON_WEB_PORTS = {80, 81, 82, 88, 443, 8000, 8080, 8443, 8888}
LEDGER_COLS = ["ip", "port", "hits", "scanned_at", "note"]
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def valid_host(h):
    """ip 列必须是 IPv4/IPv6 字面量或合法主机名; 空值/含空格的脏数据一律拒掉,
    否则会拿 ":80" 这种目标去发请求。"""
    if not h or any(c.isspace() for c in h):
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # 形如 IPv4 的点分数字串解析失败 = 越界地址(如 192.168.1.256), 不能当主机名放过
    if re.fullmatch(r"[\d.]+", h):
        return False
    return bool(HOSTNAME_RE.match(h))


def load_targets(path):
    """返回 (targets, skipped)。skipped 记被丢弃的行数及原因, 供上层提示。"""
    with open(path, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    targets, skipped, seen = [], [], set()
    for ln, r in enumerate(rows, start=2):   # 第 1 行是表头
        ip = (r.get("ip") or "").strip()
        try:
            port = int((r.get("port") or "").strip())
        except (KeyError, ValueError):
            skipped.append(f"第{ln}行: 端口非法 ({r.get('port')!r})")
            continue
        if not valid_host(ip):
            skipped.append(f"第{ln}行: IP 非法 ({ip!r})")
            continue
        if not (0 < port < 65536):
            skipped.append(f"第{ln}行: 端口越界 ({port})")
            continue
        if (ip, port) in seen:               # 重复行会白扫两次并让 findings 重复
            skipped.append(f"第{ln}行: 重复目标 ({ip}:{port})")
            continue
        seen.add((ip, port))
        targets.append({"ip": ip, "port": port})
    return targets, skipped


def load_rules(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("rules", [])


class Pacer:
    """跨 IP 并发, 单 IP 严格串行且两次请求间隔 >= interval 秒(从上次结束算起)"""
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
        return lock

    def release(self, ip, lock):
        with self._g:
            self._last[ip] = time.time()   # 从请求结束时刻起算间隔
        lock.release()

    @contextmanager
    def slot(self, ip):
        """给非 HTTP 探针用: with pacer.slot(ip): ...一次完整探测..."""
        lock = self.acquire(ip)
        try:
            yield
        finally:
            self.release(ip, lock)


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


EXCLUDE_CODE_RE = re.compile(r"^\d{3}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
                         r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


ASCII_WORD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


def word_in(needle, haystack):
    """排除词匹配。对纯 ASCII 单词用词边界, 其它(中文/以符号开头结尾如 <html、
    function() 用裸子串。

    裸子串会让 ASCII 排除词误杀合法内容: "login" 命中 login_time / last_login /
    loginCount 这些设备配置常见字段, "401" 命中序列号 SN4012233。
    词边界下 "login" 不再匹配 login_time(_ 是单词字符), 但仍匹配 "login.html"、
    "please login" 这类真正的登录页特征。

    中文与符号类排除词必须保持子串匹配: \\b 在中文之间不成立(登入畫面 会漏判),
    <html 以 < 开头也没有边界, 用词边界会让这些真正的排除特征失效。"""
    if ASCII_WORD_RE.match(needle):
        return re.search(r"\b" + re.escape(needle) + r"\b", haystack, re.I) is not None
    return needle.lower() in haystack


def evaluate_http(status, body, rule):
    if status >= 400:
        return None
    b = body.lower()
    for x in rule.get("exclude_any", []):
        # 纯 3 位数字视为 HTTP 状态码, 只在状态层面生效, 不参与 body 匹配。
        # 否则响应体里恰好含 "401" 的真命中(如序列号 SN4012233)会被误杀。
        if EXCLUDE_CODE_RE.match(x.strip()):
            continue
        if word_in(x.lower(), b):
            return None
    if len(body) < rule.get("min_len", 0):
        return None
    mock = any(x.lower() in b for x in rule.get("fake_hints", []))
    matches = [x.lower() for x in rule.get("match_any", [])]
    hits = [m for m in matches if m in b]
    if matches and not hits:
        return None
    # min_hits: 要求命中多个特征词才判定。泛词规则(如 match_any 含 uid/channel/user
    # 这类普通页面也有的词)必须设 >1, 否则任何含该词的 200 页面都会误报。
    if len(hits) < rule.get("min_hits", 1):
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
        # 双差分: 等间隔后无 cookie 复现一次, 不可复现则丢弃
        lock = pacer.acquire(ip)
        try:
            r2 = http_get(url, timeout, method, body, ctype)
        finally:
            pacer.release(ip, lock)
        if r2 and evaluate_http(*r2, rule):
            out.append({"type": "http", "url": url, **v})
    return out


RECV_MAX_BYTES = 65536   # 单条 RTSP 响应上限: SDP 远小于此, 防止畸形 Content-Length 撑爆内存


def recv_all(s):
    """收一条 RTSP 响应。响应头结束(第一个 CRLFCRLF)后再按 Content-Length 把 body 收满,
    否则 SDP 正文可能被截断, 导致 v=0 / m=video 判据漏判(假阴性)。
    总量上限 RECV_MAX_BYTES: 不信任服务端给的 Content-Length。"""
    data = b""
    try:
        while len(data) < RECV_MAX_BYTES:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" not in data:
                continue
            head, _, body = data.partition(b"\r\n\r\n")
            clen = 0
            for ln in head.decode("utf-8", "replace").splitlines():
                if ln.lower().startswith("content-length:"):
                    try:
                        clen = int(ln.split(":", 1)[1].strip())
                    except ValueError:
                        clen = 0
                    break
            if len(body) >= clen:
                break
    except OSError:
        pass
    return data.decode("utf-8", "replace")


def rtsp_probe(ip, port, timeout, interval=1.0):
    """v2 严格判据: DESCRIBE 200 且响应含 SDP(v=0 + m=video/audio) 才命中;
    OPTIONS-only / DESCRIBE 无 SDP 一律丢弃(防误报噪音, 08-22 实战教训)。
    同一连接内多个 DESCRIBE 之间也按 interval 节流(合规: 不对单 IP 连发)。"""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        if "RTSP/1.0 200" not in recv_all(s):
            s.close()
            return []
        described = None
        for path in RTSP_STREAMS:
            time.sleep(interval)
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
                     "snippet": "OPTIONS+DESCRIBE 200 且 SDP 含视频/音频流 → 未授权可拉流",
                     "probe_port": port}]
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
                 "snippet": "anonymous 230, 目录: " + ", ".join(names),
                 "probe_port": port}]
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
    p.add_argument("--resume", action="store_true",
                   help="断点续跑：据 <out>.scanned.csv 台账跳过已扫完的 ip:port(含零命中)")
    p.add_argument("--ledger", help="进度台账路径(默认 <out 去扩展名>.scanned.csv)")
    args = p.parse_args()

    targets, skipped = load_targets(args.targets)
    if skipped:
        print(f"== 输入提示: {len(skipped)} 行被跳过（空 IP / 端口非法 / 端口越界）==")
        for msg in skipped[:5]:
            print(f"    - {msg}")
        if len(skipped) > 5:
            print(f"    ... 另有 {len(skipped) - 5} 行")
    if not targets and not args.resume:
        print("== 错误: 没有可扫描的目标（检查 targets.csv 格式：表头 ip,port）==")
        sys.exit(1)
    rules = load_rules(args.rules)

    cols = ["ip", "port", "probe_port", "rule_id", "rule_name", "severity", "type", "url",
            "hits", "mock", "needs_review", "cloud_suspect", "isp", "org", "as",
            "snippet", "note"]
    ledger_path = args.ledger or os.path.splitext(args.out)[0] + ".scanned.csv"
    write_lock = threading.Lock()

    def append_findings(items):
        """增量落盘命中, 与台账同锁写入 —— 进程被杀时二者保持一致, 续跑不丢命中"""
        if not items:
            return
        new = not os.path.isfile(args.out) or os.path.getsize(args.out) == 0
        with open(args.out, "a", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            if new:
                w.writeheader()
            for r in items:
                row = {k: r.get(k, "") for k in cols}
                if isinstance(row.get("hits"), list):
                    row["hits"] = ",".join(row["hits"])
                w.writerow(row)

    def write_ledger(ip, port, items, error=""):
        """在 findings 落盘之后追加台账(含零命中)。
        error 非空 = 该目标扫描抛异常, 记为失败(续跑会重试), 不当成已完成。"""
        new = not os.path.isfile(ledger_path)
        with open(ledger_path, "a", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=LEDGER_COLS, extrasaction="ignore")
            if new:
                w.writeheader()
            w.writerow({"ip": ip, "port": port, "hits": len(items),
                        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "note": error or ("0" if not items else "")})
    done_keys = set()
    old_findings = []
    if args.resume:
        if os.path.isfile(ledger_path):
            with open(ledger_path, encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    if not row.get("ip"):
                        continue
                    # note 以 ERROR 开头 = 上次扫描异常, 不算完成, 续跑重试
                    if str(row.get("note", "")).startswith("ERROR"):
                        continue
                    done_keys.add((row["ip"].strip(), str(row.get("port", "")).strip()))
        else:
            # 兼容旧 run: 没台账时退回按 findings 推导(零命中目标会被重扫)
            print(f"== 提示: 未找到台账 {ledger_path}，退回按 findings 推导已完成目标 ==")
            if os.path.isfile(args.out):
                with open(args.out, encoding="utf-8-sig") as f:
                    for row in csv.DictReader(f):
                        done_keys.add((row.get("ip", ""), str(row.get("port", ""))))
        if os.path.isfile(args.out):
            with open(args.out, encoding="utf-8-sig") as f:
                old_findings = list(csv.DictReader(f))
        before = len(targets)
        targets = [t for t in targets if (t["ip"], str(t["port"])) not in done_keys]
        print(f"== 断点续跑: 已完成 {before - len(targets)} 个目标, "
              f"剩余 {len(targets)} 个待扫, 已有 {len(old_findings)} 条 findings ==")

    print(f"== 目标 {len(targets)} 个 | 规则 {len(rules)} 条 | "
          f"间隔 {args.interval}s | 并发 {args.workers} ==")

    pacer = Pacer(args.interval)
    findings, fl = [], threading.Lock()
    geo_cache, geo_lock = {}, threading.Lock()
    done = [0]

    def probe_ports(port, rule_port):
        """优先探目标行自己的端口; 目标行是常见 Web 端口时不再拿它探 RTSP/FTP"""
        if port == rule_port:
            return [rule_port]
        if port in COMMON_WEB_PORTS:
            return [rule_port]
        return [port, rule_port]

    failures = []
    io_errors = []

    def work(t):
        """单个目标完整扫描。扫描异常与落盘异常都在此收敛, 不让一个坏目标/一次写盘失败
        炸掉整轮。失败目标不写「已完成」, 续跑会重试。"""
        ip, port = t["ip"], t["port"]
        try:
            res = scan_target(ip, port)
        except Exception as e:
            err = f"ERROR {type(e).__name__}: {e}"[:180]
            _record_failure(ip, port, err)
            return []
        with fl:
            findings.extend(res)
            done[0] += 1
        try:
            with write_lock:
                append_findings(res)          # 先落命中
                write_ledger(ip, port, res)   # 再记台账
        except OSError as e:
            # 磁盘满/权限不足: 不能算该目标已完成, 否则续跑会跳过它而命中丢失
            _record_failure(ip, port, f"ERROR 写盘失败 {type(e).__name__}: {e}"[:180])
            return []
        with fl:
            print(f"    完成 {done[0]}/{len(targets)} {ip}:{port} 命中 {len(res)}", flush=True)
        return res

    def _record_failure(ip, port, err):
        with fl:
            failures.append(f"{ip}:{port} {err}")
            done[0] += 1
        try:
            with write_lock:
                write_ledger(ip, port, [], err)
        except OSError as e:
            with fl:
                io_errors.append(f"{ip}:{port} 台账写入失败 {e}"[:180])
        with fl:
            print(f"    失败 {done[0]}/{len(targets)} {ip}:{port} {err}", flush=True)

    def scan_target(ip, port):
        res = []
        for rule in rules:
            rtype = rule.get("type", "http")
            if rtype == "http":
                items = http_probe(ip, port, rule, args.timeout, pacer)
            elif rtype == "rtsp":
                items = []
                for p in probe_ports(port, rule.get("port", 554)):
                    with pacer.slot(ip):
                        items.extend(rtsp_probe(ip, p, args.timeout, args.interval))
            elif rtype == "ftp":
                items = []
                for p in probe_ports(port, rule.get("port", 21)):
                    with pacer.slot(ip):
                        items.extend(ftp_probe(ip, p, args.timeout))
            else:
                items = []
            for it in items:
                it.update({"ip": ip, "port": port, "rule_id": rule.get("id", "?"),
                           "rule_name": rule.get("name", "?"),
                           "severity": rule.get("severity", "review"),
                           "note": rule.get("note", "")})
                # probe_port = 实际探测端口(可能不同于 targets 行的 port, 如行是 8080 而探 554)
                # url 由探针直接按实际端口生成, 复现时以 url / probe_port 为准
                it.setdefault("probe_port", port)
            res.extend(items)
        if args.geo:
            d = geo_lookup(ip, geo_cache, geo_lock)
            for it in res:
                it["isp"] = d.get("isp", "")
                it["org"] = d.get("org", "")
                it["as"] = d.get("as", "")
                it["cloud_suspect"] = "yes" if is_cloud(d) else "no"
        return res

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(work, targets))   # 必须消费迭代器, 否则 work 内异常被静默吞掉

    # 本轮命中已增量落盘; 这里统一重排成 severity 优先的最终文件(旧 findings 合并回去)。
    # 按 (ip, port, rule_id, url) 去重: 中断后 --resume 重扫同一目标、或输入里有重复行,
    # 都会让同一命中被追加多次, 不去重会累积。
    all_findings, seen_keys = [], set()
    for f in old_findings + findings:
        key = (str(f.get("ip", "")), str(f.get("port", "")),
               str(f.get("rule_id", "")), str(f.get("url", "")))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        all_findings.append(f)
    all_findings.sort(key=lambda f: ({"high": 0, "mid": 1, "low": 2,
                                  "review": 3}.get(f.get("severity", "review"), 9),
                                     f.get("ip", ""), f.get("rule_id", "")))
    try:
        with open(args.out, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in all_findings:
                row = {k: r.get(k, "") for k in cols}
                if isinstance(row.get("hits"), list):
                    row["hits"] = ",".join(row["hits"])
                w.writerow(row)
        print(f"== findings 已导出 {args.out} ({len(all_findings)} 条, 含旧 {len(old_findings)}) ==")
    except OSError as e:
        # 增量写入的那份仍在磁盘上, 只是没排序去重; 如实告知, 不假装成功
        print(f"== 错误: 最终 findings 重写失败 ({e}) ==")
        print(f"   {args.out} 中的增量结果仍在, 但未排序去重; 排查磁盘/权限后可重跑整理")
    print("    定级分布:", dict(Counter(f.get("severity", "review") for f in all_findings)))
    if failures:
        print(f"== 注意: {len(failures)} 个目标扫描异常, 已记台账 note 列, --resume 会重试 ==")
        for f in failures[:10]:
            print(f"    ✗ {f}")
        if len(failures) > 10:
            print(f"    ... 另有 {len(failures) - 10} 个")
    if io_errors:
        print(f"== 严重: {len(io_errors)} 个目标的台账写入失败（磁盘/权限），这些目标不会被 --resume 记住 ==")
        for e in io_errors[:5]:
            print(f"    ✗ {e}")


if __name__ == "__main__":
    main()
