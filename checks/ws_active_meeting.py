"""P2 WS 数据面鉴权（活跃会议 roomId=10000）：
有效 token / 无效 token / 无 token 对比 WS 登录+入组结果。
测试会话级操作，结束发送 leave/logout；不修改业务数据。
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
import uuid
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
HOST = _pub.web_host()
PORT = 28443
ROOM_ID = 10000
OUT = os.path.join(ROOT, 'reports', 'p2', 'ws_active_meeting.json')
CID = 'e56dce61-9881-4c4e-8672-ca8b933fcf3a'
SEC = 'de9fdfa9-7ce6-4037-a343-198d3132cc47'

def oauth(user='test00', pwd=_pub.env('SEC_TEST_PASSWORD', '')):
    basic = 'Basic ' + base64.b64encode(f'{CID}:{SEC}'.encode()).decode()
    h = {'User-Agent': 'Mozilla/5.0', 'Authorization': basic, 'Origin': BASE, 'Referer': BASE + '/webapp/', 'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.post(BASE + '/meeting-resource-server/oauth2/token', headers=h, data={'grant_type': 'password', 'username': user, 'password': pwd}, params={'t': str(int(time.time() * 1000))}, timeout=20, verify=False)
    return r.json().get('access_token', '')

def api_get(path, tok, params=None):
    r = requests.get(BASE + path, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'Mozilla/5.0'}, params=params, timeout=20, verify=False)
    try:
        return r.json()
    except Exception:
        return {}

def api_post(path, tok, data):
    r = requests.post(BASE + path, headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'Mozilla/5.0'}, data=data, timeout=20, verify=False)
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

    def connect(self, path):
        key = base64.b64encode(os.urandom(16)).decode()
        req = f'GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://{HOST}:{PORT}\r\n\r\n'.encode()
        self.s.sendall(req)
        self.s.settimeout(8)
        head = b''
        while b'\r\n\r\n' not in head:
            head += self.s.recv(1024)
        return head.split(b'\r\n\r\n')[0].split(b'\r\n')[0].decode()

    def send(self, obj):
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
        self.s.sendall(bytes(h) + bytes((b ^ m[i % 4] for (i, b) in enumerate(d))))

    def recv(self, sec=6):
        self.s.settimeout(sec)
        out = []
        end = time.time() + sec
        while time.time() < end:
            try:
                hh = self.s.recv(2)
                if len(hh) < 2:
                    break
                op = hh[0] & 15
                ln = hh[1] & 127
                if ln == 126:
                    ln = struct.unpack('>H', self.s.recv(2))[0]
                elif ln == 127:
                    ln = struct.unpack('>Q', self.s.recv(8))[0]
                d = b''
                while len(d) < ln:
                    c = self.s.recv(ln - len(d))
                    if not c:
                        break
                    d += c
                if op == 1:
                    try:
                        out.append(json.loads(d.decode('utf-8', 'replace')))
                    except Exception:
                        out.append({'text': d[:200].decode('utf-8', 'replace')})
                elif op == 8:
                    out.append({'close': struct.unpack('>H', d[:2])[0] if len(d) >= 2 else None})
                    break
            except socket.timeout:
                break
            except Exception as e:
                out.append({'error': str(e)[:80]})
                break
        return out

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

def case(label, tok, uid, appid, room_id):
    rec = {'case': label, 'token_present': bool(tok), 'status': None, 'login_resp': [], 'join_resp': [], 'extra': []}
    try:
        ws = WS()
        rec['status'] = ws.connect(f'/ngproxy/ws/wsgw?appType=24&appId={appid}&ver=2.2.3&comid=0&os=web&token={tok}')
        login = {'business': 'BASE', 'id': 10000, 'app_id': appid, 'company_id': '0', 'token': tok, 'user_id': uid, 'client_guid': str(uuid.uuid4()), 'os_type': 'web', 'mutex_type': 'web', 'force_login': 0, 'registered_user': 1, 'protocol_version': '0.0.3', 'sdk_type': 25, 'extend_info': ''}
        ws.send(login)
        rec['login_resp'] = ws.recv(5)
        ws.send({'business': 'GS', 'id': 14100, 'group_id': room_id})
        rec['join_resp'] = ws.recv(8)
        if any((str(x.get('id')) == '14101' and str(x.get('result')) in ('0', '1000000') for x in rec['join_resp'] if isinstance(x, dict))):
            rec['extra'] = ws.recv(4)
        ws.send({'business': 'GS', 'id': 14102})
        ws.send({'business': 'BASE', 'id': 10002})
        try:
            ws.recv(2)
        except Exception:
            pass
        ws.close()
    except Exception as e:
        rec['error'] = str(e)[:200]
    return rec

def main():
    tok = oauth()
    bh = {'Authorization': 'Bearer ' + tok}
    me = api_get('/meeting-resource-server/api/users/myself', tok).get('userInfo') or {}
    uid = me.get('userId')
    paas = api_get('/meeting-resource-server/security/paasAuthInfo', tok)
    appid = (paas.get('result') or {}).get('appId', '')
    rooms = api_post('/meeting-resource-server/security/roomservice/having', tok, {'roomName': '', 'curPage': 1, 'pageSize': 30, 'typeStatus': 1})
    room = None
    for r in rooms.get('roomList') or []:
        if r.get('roomId') == ROOM_ID:
            room = r
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'room_id': ROOM_ID, 'meeting_active': bool(room and (room.get('curUserCount') or 0) > 0), 'curUserCount': (room or {}).get('curUserCount'), 'user_id': uid, 'app_id': appid, 'results': []}
    res['results'].append(case('valid_token', tok, uid, appid, ROOM_ID))
    res['results'].append(case('invalid_token', 'invalid-token-1234', uid, appid, ROOM_ID))
    res['results'].append(case('no_token', '', uid, appid, ROOM_ID))
    json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1)[:3500])
if __name__ == '__main__':
    main()
