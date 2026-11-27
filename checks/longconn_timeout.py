"""P2 长连接/超时测试（只读）：
1) WS webproxy 未登录/已登录空闲超时（60s 上限，记录 ping/close）
2) HTTP 请求不完整（未发送结尾空行）的超时（45s 上限）
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import json
import os
import socket
import ssl
import struct
import time
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
HOST = _pub.web_host()
PORT = 28443
OUT = os.path.join(ROOT, 'reports', 'p2', 'longconn_timeout.json')
CID = 'e56dce61-9881-4c4e-8672-ca8b933fcf3a'
SEC = 'de9fdfa9-7ce6-4037-a343-198d3132cc47'

def oauth():
    h = {'User-Agent': 'Mozilla/5.0', 'Authorization': 'Basic ' + base64.b64encode(f'{CID}:{SEC}'.encode()).decode(), 'Origin': BASE, 'Referer': BASE + '/webapp/', 'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers=h, data={'grant_type': 'password', 'username': 'test00', 'password': _pub.env('SEC_TEST_PASSWORD', '')}, params={'t': str(int(time.time() * 1000))}, timeout=20, verify=False)
    try:
        return r.json().get('access_token', '')
    except Exception:
        return ''

def ws_idle(label, token, duration=60):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=8), server_hostname=HOST)
    key = base64.b64encode(os.urandom(16)).decode()
    req = f'GET /ngproxy/ws/webproxy/ HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://{HOST}:{PORT}\r\n\r\n'.encode()
    s.sendall(req)
    s.settimeout(8)
    head = b''
    while b'\r\n\r\n' not in head:
        head += s.recv(1024)
    events = []

    def send_cmd(obj):
        d = json.dumps(obj).encode()
        m = os.urandom(4)
        h = bytearray([129])
        n = len(d)
        if n < 126:
            h.append(128 | n)
        else:
            h.append(128 | 126)
            h += struct.pack('>H', n)
        h += m
        s.sendall(bytes(h) + bytes((b ^ m[i % 4] for (i, b) in enumerate(d))))
    t0 = time.time()
    if token:
        send_cmd({'CmdID': 1029, 'Data': {'Type': ''}})
        time.sleep(0.5)
        send_cmd({'CmdID': 1000, 'Data': {'ClientVer': '4.0', 'TerminalType': 51, 'UserName': 'test00', 'Password': '', 'Token': token, 'ForcedLogin': False, 'RoomID': 10000, 'UserType': 1, 'SupportFeatures': 'PrivateTalk,AvQosReport'}})
    deadline = t0 + duration
    s.settimeout(2)
    closed = None
    while time.time() < deadline:
        try:
            d = s.recv(512)
            if not d:
                closed = {'reason': 'eof', 'elapsed': round(time.time() - t0, 1)}
                break
            events.append({'elapsed': round(time.time() - t0, 1), 'len': len(d), 'opcode': d[0] & 15, 'hex': d[:16].hex()})
        except socket.timeout:
            continue
        except Exception as e:
            closed = {'reason': str(e)[:80], 'elapsed': round(time.time() - t0, 1)}
            break
    if closed is None:
        closed = {'reason': 'still_open_after_%ss' % duration, 'elapsed': round(time.time() - t0, 1)}
    try:
        s.close()
    except Exception:
        pass
    return {'label': label, 'token': bool(token), 'events': events[:20], 'closed': closed}

def http_incomplete(duration=45):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=8), server_hostname=HOST)
    s.sendall(f'GET /serv/v1/index/info HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n'.encode())
    t0 = time.time()
    s.settimeout(2)
    closed = None
    got = b''
    while time.time() - t0 < duration:
        try:
            d = s.recv(256)
            if not d:
                closed = {'reason': 'eof', 'elapsed': round(time.time() - t0, 1)}
                break
            got += d[:100]
        except socket.timeout:
            continue
        except Exception as e:
            closed = {'reason': str(e)[:80], 'elapsed': round(time.time() - t0, 1)}
            break
    if closed is None:
        closed = {'reason': 'still_open_after_%ss' % duration, 'elapsed': round(time.time() - t0, 1)}
    try:
        s.close()
    except Exception:
        pass
    return {'bytes': len(got), 'closed': closed}

def main():
    tok = oauth()
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'ws_anonymous_idle': ws_idle('anon', '', 60), 'ws_authed_idle': ws_idle('authed', tok, 60), 'http_incomplete': http_incomplete(45)}
    json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    for (k, v) in res.items():
        if isinstance(v, dict):
            print(k, '->', json.dumps(v, ensure_ascii=False)[:300])
if __name__ == '__main__':
    main()
