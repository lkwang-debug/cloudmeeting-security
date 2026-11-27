"""P2 WS 业务帧鉴权测试（H5 SDK 协议）：
OAuth2 登录 -> 组装 WS URL -> 发送 BASE 登录帧 -> GS 加入组 -> 观察响应 -> 登出。
只读/会话级操作，不修改业务数据；token 不落盘。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import json
import os
import random
import socket
import ssl
import struct
import time
import uuid
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
HOST = _pub.web_host()
PORT = 28443
OUT = os.path.join(ROOT, 'reports', 'p2', 'ws_runtime_auth.json')
CID = 'e56dce61-9881-4c4e-8672-ca8b933fcf3a'
SEC = 'de9fdfa9-7ce6-4037-a343-198d3132cc47'

def oauth_token(user, pwd):
    basic = 'Basic ' + base64.b64encode(f'{CID}:{SEC}'.encode()).decode()
    h = {'User-Agent': 'Mozilla/5.0', 'Authorization': basic, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers=h, data={'grant_type': 'password', 'username': user, 'password': pwd}, params={'t': str(int(time.time() * 1000))}, timeout=20, verify=False)
    return r.json().get('access_token', '')

def api_get(path, tok):
    h = {'User-Agent': 'Mozilla/5.0', 'Authorization': 'Bearer ' + tok}
    r = requests.get(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, timeout=20, verify=False)
    try:
        return r.json()
    except Exception:
        return {}

class WS:

    def __init__(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=8), server_hostname=HOST)
        self.buf = b''

    def connect(self, path):
        req = f'GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://{HOST}:{PORT}\r\n\r\n'.encode()
        self.s.sendall(req)
        self.s.settimeout(8)
        head = b''
        while b'\r\n\r\n' not in head:
            head += self.s.recv(1024)
        self.head = head.split(b'\r\n\r\n', 1)[0].decode('iso-8859-1', 'replace')
        return self.head.splitlines()[0] if self.head else ''

    def send_text(self, obj):
        data = json.dumps(obj).encode()
        mask = os.urandom(4)
        hdr = bytearray([129])
        n = len(data)
        if n < 126:
            hdr.append(128 | n)
        elif n < 65536:
            hdr.append(128 | 126)
            hdr += struct.pack('>H', n)
        else:
            hdr.append(128 | 127)
            hdr += struct.pack('>Q', n)
        hdr += mask
        self.s.sendall(bytes(hdr) + bytes((b ^ mask[i % 4] for (i, b) in enumerate(data))))

    def recv_frames(self, seconds=6):
        self.s.settimeout(seconds)
        frames = []
        end = time.time() + seconds
        while time.time() < end:
            try:
                h = self.s.recv(2)
                if len(h) < 2:
                    break
                op = h[0] & 15
                ln = h[1] & 127
                if ln == 126:
                    ln = struct.unpack('>H', self.s.recv(2))[0]
                elif ln == 127:
                    ln = struct.unpack('>Q', self.s.recv(8))[0]
                data = b''
                while len(data) < ln:
                    chunk = self.s.recv(ln - len(data))
                    if not chunk:
                        break
                    data += chunk
                item = {'op': op, 'len': len(data)}
                if op == 1:
                    try:
                        item['json'] = json.loads(data.decode('utf-8', 'replace'))
                    except Exception:
                        item['text'] = data[:300].decode('utf-8', 'replace')
                elif op == 8:
                    item['close_code'] = struct.unpack('>H', data[:2])[0] if len(data) >= 2 else None
                    frames.append(item)
                    break
                else:
                    item['raw'] = data[:80].hex()
                frames.append(item)
            except socket.timeout:
                break
            except Exception as e:
                frames.append({'error': str(e)[:120]})
                break
        return frames

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

def run_case(label, tok, user_id, app_id, do_login=True, do_join=True):
    rec = {'case': label, 'login_sent': do_login, 'join_sent': do_join, 'frames': []}
    try:
        ws = WS()
        path = f'/ngproxy/ws/wsgw?appType=24&appId={app_id}&ver=2.2.3&comid=0&os=web&token={tok}'
        rec['status_line'] = ws.connect(path)
        if do_login:
            login = {'business': 'BASE', 'id': 10000, 'app_id': app_id, 'company_id': '0', 'token': tok, 'user_id': user_id, 'client_guid': str(uuid.uuid4()), 'os_type': 'web', 'mutex_type': 'web', 'force_login': 0, 'registered_user': 1, 'protocol_version': '0.0.3', 'sdk_type': 25, 'extend_info': ''}
            ws.send_text(login)
            rec['frames'].append({'after': 'login', 'frames': ws.recv_frames(6)})
        if do_join:
            ws.send_text({'business': 'GS', 'id': 14100, 'group_id': 10000})
            rec['frames'].append({'after': 'join_group_10000', 'frames': ws.recv_frames(6)})
            ws.send_text({'business': 'GS', 'id': 14102})
            ws.send_text({'business': 'BASE', 'id': 10002})
            rec['frames'].append({'after': 'leave', 'frames': ws.recv_frames(3)})
        ws.close()
    except Exception as e:
        rec['error'] = str(e)[:200]
    return rec

def main():
    tok = oauth_token('test00', _pub.env('SEC_TEST_PASSWORD', ''))
    me = api_get('/meeting-resource-server/api/users/myself', tok)
    paas = api_get('/meeting-resource-server/security/paasAuthInfo', tok)
    user_info = me.get('userInfo') or {}
    uid = user_info.get('userId')
    app_id = (paas.get('result') or {}).get('appId', '')
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'user_id': uid, 'app_id': app_id, 'token_len': len(tok)}
    res['valid_token'] = run_case('valid_token', tok, uid, app_id, True, True)
    res['no_token'] = run_case('no_token', '', uid, app_id, True, False)
    res['invalid_token'] = run_case('invalid_token', 'invalid-token-0000', uid, app_id, True, False)
    json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1)[:3000])
if __name__ == '__main__':
    main()
