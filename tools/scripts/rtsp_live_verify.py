# -*- coding: utf-8 -*-
"""RTSP 真拉流验证 v2: DESCRIBE(SDP) -> SETUP -> PLAY -> 收到 RTP 视频包才算 confirmed
红线: 不落盘任何画面帧, 只计数 RTP 包; 结束后必发 TEARDOWN 释放会话。
注意: SETUP/PLAY 会建立流媒体会话, 严格说超出只读探测范围(不是修改配置, 但也不是
GET/OPTIONS/DESCRIBE)。仅在确认授权、且 DESCRIBE 已确认未授权拉流后, 用它做最终确认。"""
import socket, sys, time

def recv_all_rtsp(s, wait=2.0, min_wait=0.5):
    """收完整 RTSP 响应: 头 + Content-Length body"""
    s.settimeout(wait)
    buf = b''
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            c = s.recv(8192)
            if not c:
                break
            buf += c
            # 完整性判断: 头结束且 body 收满
            if b'\r\n\r\n' in buf:
                head, _, body = buf.partition(b'\r\n\r\n')
                clen = 0
                for ln in head.decode(errors='replace').splitlines():
                    if ln.lower().startswith('content-length:'):
                        try: clen = int(ln.split(':',1)[1].strip())
                        except: pass
                if len(body) >= clen:
                    break
        except socket.timeout:
            if buf and time.time() > deadline - 6:
                break
    return buf

def parse_headers(head_text):
    hdrs = {}
    lines = head_text.splitlines()
    for h in lines[1:]:
        if ':' in h:
            k, v = h.split(':', 1)
            hdrs[k.strip().lower()] = v.strip()
    status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else 0
    return status, hdrs

def verify_stream(ip, port, path='/', timeout=8):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return "554拒绝(未开RTSP)"
    except OSError as e:
        return f"网络不可达: {e}"
    s.settimeout(timeout)
    base = f"rtsp://{ip}:{port}{path}"
    try:
        # OPTIONS
        s.sendall(f"OPTIONS {base} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        r = recv_all_rtsp(s)
        st, _ = parse_headers(r.decode(errors='replace'))
        if st != 200:
            return f"OPTIONS={st}"
        # DESCRIBE
        s.sendall(f"DESCRIBE {base} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n".encode())
        r = recv_all_rtsp(s)
        text = r.decode(errors='replace')
        st, hdrs = parse_headers(text)
        if st != 200 or 'v=0' not in text:
            return f"DESCRIBE={st} 无SDP"
        sdp = text.partition('\r\n\r\n')[2]
        # control 路径
        control = path
        has_video_track = 'm=video' in sdp
        for ln in sdp.splitlines():
            if ln.startswith('a=control:') and 'rtsp://' not in ln:
                c = ln.split(':', 1)[1].strip()
                if c and c != '*':
                    control = c if c.startswith('/') else f"{path.rstrip('/')}/{c}"
                    break
        if not has_video_track:
            return "SDP无m=video(纯音频)"
        track_url = control if control.startswith('rtsp://') else f"rtsp://{ip}:{port}{control}"
        # SETUP (TCP interleaved)
        s.sendall(f"SETUP {track_url} RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n".encode())
        r = recv_all_rtsp(s)
        st, hs = parse_headers(r.decode(errors='replace'))
        if st != 200:
            return f"SETUP={st}"
        session = hs.get('session', '').split(';')[0]
        sess_hdr = f"Session: {session}\r\n" if session else ''
        # PLAY
        s.sendall(f"PLAY {track_url} RTSP/1.0\r\nCSeq: 4\r\n{sess_hdr}\r\n".encode())
        r = recv_all_rtsp(s)
        st, _ = parse_headers(r.decode(errors='replace'))
        if st != 200:
            return f"PLAY={st}"
        # 数 RTP interleaved 视频包(channel 0)
        rtp_pkts = video_bytes = 0
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                data = s.recv(16384)
            except socket.timeout:
                break
            if not data:
                break
            i = 0
            while i + 4 <= len(data):
                if data[i:i+1] == b'$':
                    ch = data[i+1]
                    pkt_len = int.from_bytes(data[i+2:i+4], 'big')
                    payload = data[i+4:i+4+pkt_len]
                    if ch == 0:
                        rtp_pkts += 1
                        video_bytes += len(payload)
                    i += 4 + pkt_len
                else:
                    i += 1
        # 释放会话, 不在目标上留下悬挂的流媒体会话
        try:
            s.sendall(f"TEARDOWN {track_url} RTSP/1.0\r\nCSeq: 5\r\n{sess_hdr}\r\n\r\n".encode())
            recv_all_rtsp(s, wait=1.0)
        except Exception:
            pass
        if rtp_pkts >= 10 and video_bytes > 5000:
            return f"LIVE_CONFIRMED pkts={rtp_pkts} bytes={video_bytes} track={track_url}"
        return f"PLAY成功但数据不足 pkts={rtp_pkts} bytes={video_bytes}"
    except socket.timeout:
        return "超时"
    except ConnectionRefusedError:
        return "554拒绝(未开RTSP)"
    except OSError as e:
        return f"网络不可达: {e}"
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"
    finally:
        try: s.close()
        except: pass

if __name__ == '__main__':
    for t in sys.argv[1:]:
        parts = t.split(':')
        ip = parts[0]
        ports = [int(p) for p in parts[1:]] if len(parts) > 1 else [554]
        for port in ports:
            print(f"{ip}:{port} -> {verify_stream(ip, port)}", flush=True)
