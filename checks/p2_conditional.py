"""P2 条件性检测（自动识别 + 只读探测）：
- 从 JS chunk 自动识别 WS/SSE/long-poll 候选；
- 网关走私：CL.TE / TE.CL / TE 混淆原始报文（只读，不投递利用载荷）；
- 缓存：缓存头/X-Forwarded-Host 反射；
- 长连接：text/event-stream 探测。
输出 reports/p2/conditional.json + P2_CONDITIONAL.md
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get('SEC_TARGET', _pub.target())
HOST = urllib.parse.urlparse(BASE).hostname
PORT = urllib.parse.urlparse(BASE).port or 443
CHUNKS = os.path.join(ROOT, 'tools_cache', 'chunks')
OUT = os.path.join(ROOT, 'reports', 'p2')

def detect_candidates():
    kws = [b'wss://', b'ws://', b'WebSocket', b'EventSource', b'text/event-stream', b'/sse', b'/ws']
    hits = {}
    if os.path.isdir(CHUNKS):
        for fn in os.listdir(CHUNKS):
            try:
                d = open(os.path.join(CHUNKS, fn), 'rb').read()
            except Exception:
                continue
            found = [k.decode() for k in kws if k.lower() in d.lower()]
            if found:
                hits[fn] = found
    return hits

def http_get(path, headers=None):
    h = {'User-Agent': 'Mozilla/5.0', 'Origin': BASE, 'Referer': BASE + '/ui/login'}
    if headers:
        h.update(headers)
    r = requests.get(BASE + path, headers=h, timeout=15, verify=False)
    return {'http': r.status_code, 'headers': {k: v for (k, v) in r.headers.items() if k.lower() in ('server', 'cache-control', 'age', 'x-cache', 'vary', 'location', 'content-type', 'x-powered-by', 'via')}, 'body_len': len(r.content), 'body_head': r.text[:120]}

def raw_request(data, read_timeout=4.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=8), server_hostname=HOST)
    s.settimeout(read_timeout)
    try:
        s.sendall(data)
        buf = b''
        t0 = time.time()
        try:
            while len(buf) < 4000 and time.time() - t0 < read_timeout:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b'\r\n\r\n' in buf:
                    break
        except socket.timeout:
            pass
        return {'elapsed': round(time.time() - t0, 2), 'bytes': len(buf), 'head': buf[:180].decode('iso-8859-1', 'replace')}
    finally:
        s.close()

def smuggling_probes():
    results = []
    base = f'POST /serv/v1/index/info HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nOrigin: {BASE}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n'.encode()
    results.append({'name': 'baseline', **raw_request(base)})
    cases = {'cl_te': f'POST /serv/v1/index/info HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n'.encode(), 'te_cl': f'POST /serv/v1/index/info HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n'.encode(), 'te_obfuscated': f'POST /serv/v1/index/info HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nTransfer-Encoding: xchunked\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n'.encode()}
    for (name, data) in cases.items():
        results.append({'name': name, **raw_request(data)})
    return results

def main():
    os.makedirs(OUT, exist_ok=True)
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE}
    res['ws_sse_candidates'] = detect_candidates()
    res['cache'] = []
    for path in ('/serv/v1/index/info', '/ui/login', '/'):
        base = http_get(path)
        xfh = http_get(path, {'X-Forwarded-Host': 'oast-cache.example.com', 'Cache-Control': 'no-cache'})
        res['cache'].append({'path': path, 'base': base, 'xfh': xfh, 'xfh_reflected': 'oast-cache.example.com' in json.dumps(xfh)})
    res['longconn'] = []
    for path in ('/serv/v1/index/info', '/serv/v1/recording/paastask'):
        r = requests.get(BASE + path, headers={'Accept': 'text/event-stream', 'User-Agent': 'Mozilla/5.0'}, params={'t': str(int(time.time() * 1000))}, timeout=10, verify=False, stream=True)
        res['longconn'].append({'path': path, 'http': r.status_code, 'content_type': r.headers.get('Content-Type'), 'cache_control': r.headers.get('Cache-Control')})
        r.close()
    res['smuggling'] = smuggling_probes()
    json.dump(res, open(os.path.join(OUT, 'conditional.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    lines = ['# P2 条件性检测（自动识别 + 只读探测）', '', f"- 时间：{res['generated_at']}", f'- 目标：{BASE}', '', '## 1. WS/SSE/long-poll 自动识别（JS chunk）', '']
    if res['ws_sse_candidates']:
        for (fn, kws) in res['ws_sse_candidates'].items():
            lines.append(f'- {fn}: {kws}')
    else:
        lines.append('- 未在已下载 chunk 中发现 WS/SSE 关键字')
    lines += ['', '## 2. 缓存探测', '', '| 路径 | 基础状态 | 缓存头 | XFH 反射 |', '|---|---|---|---|']
    for c in res['cache']:
        lines.append(f"| {c['path']} | {c['base']['http']} | {c['base']['headers']} | {c['xfh_reflected']} |")
    lines += ['', '## 3. 长连接/SSE 探测', '']
    for c in res['longconn']:
        lines.append(f"- {c['path']}: http={c['http']} content-type={c['content_type']} cache={c['cache_control']}")
    lines += ['', '## 4. 网关走私探测（只读原始报文）', '']
    for s in res['smuggling']:
        lines.append(f"- {s['name']}: elapsed={s.get('elapsed')} bytes={s.get('bytes')} head={s.get('head', '')[:120]!r}")
    lines += ['', '## 5. 结论', '', '- 本模块为 P2 条件性检测的首轮：WS/SSE 候选自动识别、缓存头/XFH、长连接、走私 CL.TE/TE.CL 只读探测；', '- 竞态（race）与写路径条件测试需写白名单与隔离数据，列为下一轮 P2。']
    open(os.path.join(OUT, 'P2_CONDITIONAL.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    print('written:', os.path.join(OUT, 'P2_CONDITIONAL.md'))
    print('candidates:', res['ws_sse_candidates'])
    print('smuggling:', [(s['name'], s.get('elapsed'), s.get('bytes')) for s in res['smuggling']])
if __name__ == '__main__':
    main()
