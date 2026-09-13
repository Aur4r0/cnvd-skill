#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bing 检索 v3：解析 ck/a 跳转链接 + 标题。"""
import re, base64, time, urllib.parse, urllib.request

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36",
      "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}

def realurl(ck):
    m = re.search(r'[?&]u=a1([^&]+)', ck)
    if m:
        b = m.group(1)
        b += '=' * (-len(b) % 4)
        try:
            return base64.urlsafe_b64decode(b).decode('utf-8', errors='replace')
        except Exception:
            return ck
    return ck

def search(q, count=15):
    url = "https://www.bing.com/search?q=%s&count=%d" % (urllib.parse.quote(q), count)
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=25) as r:
        h = r.read().decode("utf-8", errors="ignore")
    blocks = h.split('<li class="b_algo"')[1:]
    out = []
    for it in blocks:
        # 标题在 <h2> 或 a[aria-label/class tilk] 后的锚文本
        m = re.search(r'<h2[^>]*>\s*<a[^>]*>(.*?)</a>', it, re.S)
        if not m:
            m = re.search(r'<a[^>]*class="tilk"[^>]*href="([^"]+)"[^>]*aria-label="([^"]+)"', it)
            if m:
                out.append((m.group(2), realurl(m.group(1))))
                continue
        if m:
            title = re.sub(r'<[^>]+>', '', m.group(1)).strip()
            mu = re.search(r'href="(https://www\.bing\.com/ck/a[^"]+|http[^"]+)"', it)
            u = realurl(mu.group(1)) if mu else ''
            out.append((title[:90], u[:120]))
    nores = ('没有找到' in h) or ('No results found' in h) or ('查无结果' in h)
    if not out and len(blocks) > 0:
        # 兜底：aria-label 域名提示
        for it in blocks:
            ma = re.search(r'<a[^>]*class="tilk"[^>]*href="([^"]+)"[^>]*aria-label="([^"]+)"', it)
            mt = re.search(r'<h2[^>]*>(?:\s*<a[^>]*>)?(.*?)</(?:a|h2)>', it, re.S)
            if mt:
                title = re.sub(r'<[^>]+>', '', mt.group(1)).strip()
                u = realurl(ma.group(1)) if ma else '(ck-link)'
                out.append((title[:90], u[:120]))
    return out, nores

if __name__ == '__main__':
    queries = [
        '"RecoverPasswordBySuperPassword"',
        '"SuperPasswordQRCode"',
        'p6scloud',
        '"RecoverPasswordBySaveQuestion"',
        '"SaveQuestionList" NVR',
        '云视通 超级密码 漏洞',
        'NVR 超级密码 兑换码 未授权',
        'YLT NVR UID 漏洞',
        'site:cnvd.org.cn 超级密码',
        'site:cnvd.org.cn 录像机 密码 找回',
        '中维世纪 NVR 漏洞',
        'CloudSEE Jovision password reset vulnerability',
    ]
    for q in queries:
        try:
            res, nores = search(q)
            print("== Q: %s" % q)
            if not res:
                print("   [检索无结果]" if nores else "   [无可解析条目]")
            for t, u in res[:8]:
                print("   -", t, "|", u)
        except Exception as e:
            print("== Q: %s\n   [ERROR] %s" % (q, e))
        time.sleep(2.8)
