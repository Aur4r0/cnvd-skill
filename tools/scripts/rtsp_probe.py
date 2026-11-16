import socket, sys, time

INTERVAL = 1.0   # 单 IP 请求间隔 >=1s（合规红线）

def desc(ip, port=554, path='/'):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    try:
        s.connect((ip, port))
        req = f"OPTIONS rtsp://{ip}:{port}/{path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: VLC/3.0\r\n\r\n"
        s.send(req.encode())
        data = s.recv(4096).decode(errors='replace')
        if '200' not in data.split('\r\n')[0]:
            return f"OPTIONS非200: {data.splitlines()[0][:60]}"
        # 发 DESCRIBE（与 OPTIONS 之间保持合规间隔）
        time.sleep(INTERVAL)
        req = f"DESCRIBE rtsp://{ip}:{port}/{path} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\nUser-Agent: VLC/3.0\r\n\r\n"
        s.send(req.encode())
        s.settimeout(8)
        buf = b''
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                buf += chunk
                if b'\r\n\r\n' in buf and len(buf) > 2000: break
            except socket.timeout:
                break
        text = buf.decode(errors='replace')
        first = text.splitlines()[0] if text else '(空)'
        has_sdp = ('v=0' in text) and ('m=video' in text or 'm=audio' in text)
        sdp = [l for l in text.splitlines() if l.startswith(('v=','m=','a='))][:6]
        auth = '401' in text or 'Unauthorized' in text
        return f"{first} | SDP={'YES' if has_sdp else 'NO'} | auth={auth} | {sdp}"
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"
    finally:
        s.close()

for target in sys.argv[1:]:
    ip, port = target.split(':') if ':' in target else (target, '554')
    try:
        port = int(port)
    except ValueError:
        print(f"{target} -> 跳过: 端口非法")
        continue
    for i, p in enumerate(['/', '/live', '/stream1', '/ch1/main', '/1']):
        if i:
            time.sleep(INTERVAL)   # 同一目标的后续路径探测之间加间隔
        r = desc(ip, port, p)
        print(f"{ip}:{port}{p} -> {r}")
        if 'SDP=YES' in r: break
    print()
