"""P2 WS 运行时（续）：默认模板创建 secauto 房间 -> 详情/直播地址 -> WS 握手 -> 清理。"""
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
OUT = os.path.join(ROOT, 'reports', 'p2', 'ws_runtime.json')
HOST = urllib.parse.urlparse(BASE).hostname
PORT = urllib.parse.urlparse(BASE).port or 443
PREFIX = 'secauto_ws_'

def hdr():
    return {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': open(TOK, encoding='utf-8').read().strip(), 'Content-Type': 'application/json'}

def req(method, path, body=None):
    r = requests.request(method, BASE + path, headers=hdr(), params={'t': str(int(time.time() * 1000))}, json=body, timeout=20, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {'raw': r.text[:300]})

def list_rooms():
    (st, j) = req('POST', '/meeting/v1/roominfo/page', {'pageNumber': 1, 'pageSize': 200})
    recs = (j.get('data') or {}).get('records') or []
    return [r for r in recs if str(r.get('roomName', '')).startswith(PREFIX)]

def ws_handshake(host, port, path, token=''):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    lines = [f'GET {path} HTTP/1.1', f'Host: {host}:{port}', 'Upgrade: websocket', 'Connection: Upgrade', 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==', 'Sec-WebSocket-Version: 13', 'Origin: ' + BASE]
    if token:
        lines.append('token: ' + token)
    try:
        s = ctx.wrap_socket(socket.create_connection((host, port), timeout=8), server_hostname=host)
        s.settimeout(5)
        s.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode())
        buf = b''
        try:
            while len(buf) < 1500:
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if b'\r\n\r\n' in buf:
                    break
        except socket.timeout:
            pass
        s.close()
        head = buf.split(b'\r\n\r\n', 1)[0].decode('iso-8859-1', 'replace')
        return {'status': head.splitlines()[0] if head else '', 'head': head[:400]}
    except Exception as e:
        return {'error': str(e)[:150]}

def main():
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'steps': {}}
    tok = open(TOK, encoding='utf-8').read().strip()
    rooms = list_rooms()
    res['existing'] = [{'roomID': r.get('roomID'), 'roomName': r.get('roomName')} for r in rooms]
    if not rooms:
        (st, j) = req('GET', '/meeting/v1/roominfo/default')
        d = dict(j.get('data') or {})
        d['roomName'] = PREFIX + time.strftime('%m%d%H%M%S')
        (st, j2) = req('POST', '/meeting/v1/roominfo/add', d)
        res['steps']['create'] = {'http': st, 'code': j2.get('code'), 'msg': j2.get('msg')}
        rooms = list_rooms()
    res['rooms'] = [{'roomID': r.get('roomID'), 'roomName': r.get('roomName')} for r in rooms]
    if rooms:
        rid = rooms[0]['roomID']
        (st, j) = req('GET', f'/meeting/v1/roominfo/get/{rid}')
        res['steps']['get'] = {'http': st, 'code': j.get('code'), 'body': json.dumps(j, ensure_ascii=False)[:1000]}
        (st, j) = req('POST', '/serv/v1/live/getLiveAddr', {'roomID': rid})
        res['steps']['live_addr'] = {'http': st, 'code': j.get('code'), 'body': json.dumps(j, ensure_ascii=False)[:400]}
        res['steps']['ws'] = []
        for path in ('/websocket', '/ws', '/meeting/ws', '/live/ws', '/ws/room'):
            for (tname, t) in (('admin', tok), ('none', '')):
                r = ws_handshake(HOST, PORT, path, t)
                res['steps']['ws'].append({'path': path, 'token': tname, **r})
    res['cleanup'] = []
    for r in rooms:
        rid = r.get('roomID')
        for body in ({'roomID': rid}, {'roomIds': [rid]}):
            (st, j) = req('POST', '/meeting/v1/roominfo/delete', body)
            res['cleanup'].append({'roomID': rid, 'body': body, 'http': st, 'code': j.get('code'), 'msg': j.get('msg')})
            if str(j.get('code')) == '0':
                break
    res['remaining'] = [{'roomID': r.get('roomID'), 'roomName': r.get('roomName')} for r in list_rooms()]
    json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1)[:2500])
if __name__ == '__main__':
    main()
