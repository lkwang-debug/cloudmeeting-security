"""P2 WS 运行时：创建 secauto 测试会议室 -> 获取地址 -> WS 握手探测 -> 清理。
仅写 secauto_* 数据；结束必删。输出 reports/p2/ws_runtime.json
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
TOK = os.path.join(ROOT, 'evidence', 'tokens', 'admin.txt')
OUT = os.path.join(ROOT, 'reports', 'p2')
TS = time.strftime('%m%d%H%M%S')
NAME = f'secauto_ws_{TS}'
HOST = urllib.parse.urlparse(BASE).hostname
PORT = urllib.parse.urlparse(BASE).port or 443

def hdr():
    return {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': open(TOK, encoding='utf-8').read().strip(), 'Content-Type': 'application/json'}

def post(path, body):
    r = requests.post(BASE + path, headers=hdr(), params={'t': str(int(time.time() * 1000))}, json=body, timeout=20, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {'raw': r.text[:300]})

def get(path):
    r = requests.get(BASE + path, headers=hdr(), params={'t': str(int(time.time() * 1000))}, timeout=20, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {'raw': r.text[:300]})

def ws_handshake(host, port, path, token='', timeout=6):
    """原始 WS 握手（wss），返回状态行/响应头。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    key = 'dGhlIHNhbXBsZSBub25jZQ=='
    lines = [f'GET {path} HTTP/1.1', f'Host: {host}:{port}', 'Upgrade: websocket', 'Connection: Upgrade', f'Sec-WebSocket-Key: {key}', 'Sec-WebSocket-Version: 13', 'Origin: ' + BASE]
    if token:
        lines.append('token: ' + token)
    req = ('\r\n'.join(lines) + '\r\n\r\n').encode()
    s = ctx.wrap_socket(socket.create_connection((host, port), timeout=8), server_hostname=host)
    s.settimeout(timeout)
    try:
        s.sendall(req)
        buf = b''
        try:
            while len(buf) < 2000:
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if b'\r\n\r\n' in buf:
                    break
        except socket.timeout:
            pass
        head = buf.split(b'\r\n\r\n', 1)[0].decode('iso-8859-1', 'replace')
        status = head.splitlines()[0] if head else ''
        return {'status_line': status, 'head': head[:500]}
    finally:
        s.close()

def main():
    os.makedirs(OUT, exist_ok=True)
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'room_name': NAME, 'steps': {}}
    body = {'roomType': '1', 'roomName': NAME, 'roomDesc': 'secauto test room', 'password': 'E10ADC3949BA59ABBE56E057F20F883E', 'verifyMode': '1', 'maxUserCount': 5, 'status': '1', 'departID': 1, 'enableChairPwd': '1', 'chairPassword': 'E10ADC3949BA59ABBE56E057F20F883E', 'useDefaultFlag': '1', 'defaultMode': '0', 'cycleFlag': '1', 'enableRecord': '0'}
    (st, j) = post('/meeting/v1/roominfo/add', body)
    res['steps']['create'] = {'http': st, 'code': j.get('code'), 'msg': j.get('msg'), 'body': json.dumps(j, ensure_ascii=False)[:400]}
    print('create:', st, j.get('code'), j.get('msg'))
    rid = None
    data = j.get('data')
    if isinstance(data, dict):
        rid = data.get('roomID') or data.get('roomId') or data.get('id')
    if not rid:
        (st, j2) = post('/meeting/v1/roominfo/page', {'pageNumber': 1, 'pageSize': 50, 'roomName': NAME})
        recs = (j2.get('data') or {}).get('records') or []
        for r in recs:
            if r.get('roomName') == NAME:
                rid = r.get('roomID')
    res['room_id'] = rid
    print('roomID:', rid)
    try:
        if rid:
            (st, j) = get(f'/meeting/v1/roominfo/get/{rid}')
            res['steps']['get'] = {'http': st, 'code': j.get('code'), 'body': json.dumps(j, ensure_ascii=False)[:800]}
            print('get:', st, j.get('code'))
            (st, j) = post('/serv/v1/live/getLiveAddr', {'roomID': rid})
            res['steps']['live_addr'] = {'http': st, 'code': j.get('code'), 'body': json.dumps(j, ensure_ascii=False)[:500]}
            print('getLiveAddr:', st, j.get('code'), json.dumps(j, ensure_ascii=False)[:200])
            tokens = {'admin': open(TOK, encoding='utf-8').read().strip(), 'none': ''}
            for (name, tok) in tokens.items():
                res['steps'].setdefault('ws', {})[name] = []
                for path in ('/websocket', '/ws', '/meeting/ws', '/live/ws'):
                    r = ws_handshake(HOST, PORT, path, tok)
                    res['steps']['ws'][name].append({'path': path, **r})
                    print(f"ws {name} {path}: {r['status_line'][:60]}")
    finally:
        if rid:
            for body in ({'roomID': rid}, {'roomIds': [rid]}, {'ids': [rid]}):
                (st, j) = post('/meeting/v1/roominfo/delete', body)
                res['steps'].setdefault('cleanup', []).append({'body': body, 'http': st, 'code': j.get('code'), 'msg': j.get('msg')})
                print('cleanup:', st, j.get('code'), j.get('msg'))
                if str(j.get('code')) == '0':
                    break
            (st, j) = post('/meeting/v1/roominfo/page', {'pageNumber': 1, 'pageSize': 50, 'roomName': NAME})
            left = [r for r in (j.get('data') or {}).get('records') or [] if r.get('roomName') == NAME]
            res['cleanup_remaining'] = len(left)
            print('remaining:', len(left))
    json.dump(res, open(os.path.join(OUT, 'ws_runtime.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('written ws_runtime.json')
if __name__ == '__main__':
    main()
