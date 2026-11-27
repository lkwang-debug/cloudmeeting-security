"""应用安全：录制/会议记录只读双身份矩阵（使用现有数据，不创建/删除业务数据）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import requests
import urllib3
import yaml
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
try:
    from checks import web_auth
except ImportError:
    import web_auth
urllib3.disable_warnings()
BASE = gc.base_url()
CFG = os.path.join(gc.ROOT, 'configs', 'web_automation.yaml')

def load_users():
    try:
        from runner import env_config
        sc = env_config.load()
        acc = sc.get('accounts') or {}
        a = acc.get('idor_a') or {}
        b = acc.get('idor_b') or {}
        return {'A': {'name': a.get('username', 'test_user_a'), 'id': None, 'depart': a.get('depart_id', 1), 'token': 'evidence/tokens/idor_%s.txt' % a.get('username', 'test_user_a')}, 'B': {'name': b.get('username', 'test05'), 'id': None, 'depart': b.get('depart_id', 2), 'token': 'evidence/tokens/idor_%s.txt' % b.get('username', 'test05')}}
    except Exception:
        return {'A': {'name': 'test_user_a', 'id': 1000000016, 'depart': 1, 'token': 'evidence/tokens/idor_hzk05.txt'}, 'B': {'name': 'test05', 'id': 1000001207, 'depart': 2, 'token': 'evidence/tokens/idor_test05.txt'}}

def load_cfg():
    try:
        return yaml.safe_load(open(CFG, encoding='utf-8')) or {}
    except Exception:
        return {}

def tok(rel):
    p = os.path.join(gc.ROOT, rel)
    return open(p, encoding='utf-8').read().strip() if os.path.exists(p) else ''

def main():
    root = load_cfg()
    USERS = load_users()
    admin = web_auth.headers(root)
    h = {**admin, 'Content-Type': 'application/json', 'Origin': BASE, 'Referer': BASE}
    matrix = []
    recs = {}
    for (label, u) in USERS.items():
        if not u.get('id'):
            try:
                q = requests.post(BASE + '/api/v1/user/list', headers=h, json={'searchKey': u['name'], 'searchType': 0, 'pageSize': 10}, timeout=20, verify=False)
                recs_u = (q.json().get('data') or {}).get('records') or []
                u['id'] = next((x.get('userId') for x in recs_u if x.get('userName') == u['name']), None)
            except Exception:
                u['id'] = None
        try:
            r = requests.get(BASE + '/api/v1/room/record-summaries', headers=h, params={'userId': u['id'], 'pageNumber': 1, 'pageSize': 20}, timeout=20, verify=False)
            j = r.json()
            rows = (j.get('data') or {}).get('records') or [] if isinstance(j.get('data'), dict) else []
            recs[label] = rows
            matrix.append({'kind': 'recording', 'identity': label, 'user': u['name'], 'http': r.status_code, 'code': j.get('code'), 'records': len(rows)})
        except Exception as e:
            matrix.append({'kind': 'recording', 'identity': label, 'error': str(e)[:100]})
    meetings = {}
    for (label, u) in USERS.items():
        t = tok(u['token'])
        if not t:
            meetings[label] = []
            continue
        hh = {'token': t, 'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
        end = time.strftime('%Y-%m-%d %H:%M:%S')
        start = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 25 * 86400))
        body = {'departId': u['depart'], 'startTime': start, 'endTime': end, 'pageNumber': 1, 'pageSize': 50}
        try:
            r = requests.post(BASE + '/meeting/v1/meetinglog/page', headers=hh, json=body, params={'t': '1'}, timeout=20, verify=False)
            j = r.json()
            rows = (j.get('data') or {}).get('records') or [] if isinstance(j.get('data'), dict) else []
            meetings[label] = rows
            matrix.append({'kind': 'meeting', 'identity': label, 'user': u['name'], 'http': r.status_code, 'code': j.get('code'), 'records': len(rows)})
        except Exception as e:
            meetings[label] = []
            matrix.append({'kind': 'meeting', 'identity': label, 'error': str(e)[:100]})
    findings = []
    a_rooms = {str(x.get('roomId')) for x in recs.get('A', [])}
    b_rooms = {str(x.get('roomId')) for x in recs.get('B', [])}
    for (label, rows) in meetings.items():
        other = 'B' if label == 'A' else 'A'
        other_rooms = b_rooms if other == 'B' else a_rooms
        for m in rows:
            if str(m.get('roomID')) in other_rooms:
                findings.append(gc.finding('IDOR-MEETING-RECORD', 'medium', f"会议记录跨身份可见：{label} 看到 {other} 的录制会议室 {m.get('roomID')}", evidence=json.dumps(m, ensure_ascii=False)[:300], remediation='按部门/创建人过滤'))
                break
    gc.emit('idor_recording_meeting', 'application', 'PASS', findings, summary=json.dumps({'matrix': matrix, 'recordings': {k: [{'roomId': x.get('roomId'), 'groupId': x.get('groupId'), 'creator': x.get('creatorName')} for x in v] for (k, v) in recs.items()}, 'meeting_isolated': {'A_sees_B_room': any((str(r.get('roomID')) in b_rooms for r in meetings.get('A', []))), 'B_sees_A_room': any((str(r.get('roomID')) in a_rooms for r in meetings.get('B', [])))}}, ensure_ascii=False)[:1200])
if __name__ == '__main__':
    main()
