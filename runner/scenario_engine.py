"""C：多步业务场景引擎（YAML 驱动，支持 request/login/sql/assert/cleanup）。
用法：python runner/scenario_engine.py fixtures/scenarios/<name>.yaml
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import subprocess
import sys
import time
import requests
import urllib3
import yaml
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
OUT_DIR = os.path.join(ROOT, 'reports', 'final', 'scenarios')
os.makedirs(OUT_DIR, exist_ok=True)

def load_token(name='admin02'):
    p = os.path.join(ROOT, 'evidence', 'tokens', f'{name}.txt')
    return open(p, encoding='utf-8').read().strip() if os.path.exists(p) else ''

def req(method, path, body=None, token=None, params=None, extra_headers=None):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    tok = token if token is not None else load_token()
    if tok:
        h['token'] = tok
    if extra_headers:
        h.update(extra_headers)
    q = {'t': str(int(time.time() * 1000))}
    if params:
        q.update(params)
    r = requests.request(method, BASE + path, headers=h, params=q, json=body, timeout=20, verify=False)
    try:
        j = r.json()
    except Exception:
        j = {'raw': r.text[:300]}
    return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg'), 'data': j.get('data'), 'raw': json.dumps(j, ensure_ascii=False)[:500]}

def run_sql(sql):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
    cmd = 'docker exec hst-mysql mysql -h192.168.7.155 -P22007 ' + ('-u' + _pub.shell('SEC_DB_USER')) + ' -' + _pub.shell('SEC_TEST_PASSWORD') + ' --ssl-mode=REQUIRED fastmeeting -N -e ' + json.dumps(sql) + ' 2>/dev/null'
    (i, o, e) = c.exec_command(cmd, timeout=120)
    out = (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
    c.close()
    return out

def redis_del(keys):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
    R = 'docker exec hst-redis redis-cli -h ' + _pub.shell('SEC_DB_HOST') + ' -p 22002 -a ' + _pub.shell('SEC_REDIS_PASSWORD') + ' -n 0 del '
    out = []
    for k in keys:
        (i, o, e) = c.exec_command(R + k + ' 2>/dev/null', timeout=60)
        out.append((o.read().decode() + e.read().decode()).strip())
    c.close()
    return out

def login(username, password_env='SEC_BACKEND_PASS'):
    out_file = os.path.join(ROOT, 'evidence', 'tokens', f'scen_{username}.txt')
    ev_dir = os.path.join(ROOT, 'evidence', 'raw', f'scen_{username}')
    candidates = [os.environ.get('SCEN_LOGIN_PYTHON') or '', __import__('sys').executable, __import__('sys').executable]
    py_exe = next((x for x in candidates if x and os.path.exists(x)), sys.executable)
    cmd = [py_exe, os.path.join(ROOT, 'adapters', 'browser', 'admin_login.py'), '--target', _pub.target(), '--username', username, '--password-env', password_env, '--attempts', '2', '--out', out_file, '--evidence-dir', ev_dir]
    subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300)
    resp = os.path.join(ev_dir, 'login_response.json')
    code = None
    if os.path.exists(resp):
        try:
            code = json.load(open(resp, encoding='utf-8-sig')).get('code')
        except Exception:
            pass
    tok = open(out_file, encoding='utf-8').read().strip() if os.path.exists(out_file) else ''
    return {'login_code': code, 'token': tok, 'token_len': len(tok)}

def main():
    if len(sys.argv) < 2:
        print('usage: scenario_engine.py <scenario.yaml>')
        return 2
    scen = yaml.safe_load(open(sys.argv[1], encoding='utf-8'))
    name = scen.get('name', os.path.basename(sys.argv[1]))
    vars_ = dict(scen.get('vars') or {})
    vars_['ts'] = time.strftime('%m%d%H%M%S')
    for _ in range(3):
        for (k, v) in list(vars_.items()):
            if isinstance(v, str) and '${' in v:
                for (k2, v2) in vars_.items():
                    v = v.replace('${%s}' % k2, str(v2))
                vars_[k] = v
    tokens = {}
    results = {'scenario': name, 'started_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'steps': [], 'verdict': 'UNKNOWN', 'vars': {}}

    def render(obj):
        if isinstance(obj, str):
            for (k, v) in vars_.items():
                obj = obj.replace('${%s}' % k, str(v))
            return obj
        if isinstance(obj, dict):
            return {k: render(v) for (k, v) in obj.items()}
        if isinstance(obj, list):
            return [render(x) for x in obj]
        return obj

    def execute(step, phase='main'):
        st = {'phase': phase, 'name': step.get('name', step.get('action')), 'action': step.get('action')}
        try:
            act = step.get('action')
            if act == 'login':
                lg = login(render(step['username']), step.get('password_env', 'SEC_BACKEND_PASS'))
                tokens[step.get('as', step['username'])] = lg['token']
                st.update({'login_code': lg['login_code'], 'token_len': lg['token_len']})
                st['ok'] = lg['login_code'] == '0' and lg['token_len'] > 20
            elif act == 'request':
                body = render(step.get('body'))
                if step.get('body_from'):
                    base = vars_.get(step['body_from']) or {}
                    if isinstance(base, dict):
                        body = json.loads(json.dumps(base))
                        body.update(render(step.get('overrides') or {}))
                as_name = step.get('as', '')
                tok = tokens.get(as_name) if as_name else None
                if as_name and (not tok):
                    st['ok'] = False
                    st['error'] = 'no token for as=' + as_name
                    results['steps'].append(st)
                    print('FAIL', phase, st.get('name'), st['error'])
                    return st
                r = req(render(step.get('method', 'GET')).upper(), render(step['path']), body, tok, render(step.get('params')), render(step.get('headers')))
                st.update(r)
                expect = step.get('expect') or {}
                ok = True
                if 'code' in expect and str(r['code']) != str(expect['code']):
                    ok = False
                if 'http' in expect and str(r['http']) != str(expect['http']):
                    ok = False
                st['ok'] = ok
                if step.get('save'):
                    vars_[step['save']] = r['data']
            elif act == 'find_role':
                data = vars_.get(step['from']) or {}
                if isinstance(data, dict):
                    recs = data.get('records') or (data.get('data') or {}).get('records') or []
                else:
                    recs = []
                rid = None
                for r in recs or []:
                    if r.get('name') == render(step['name']):
                        rid = r.get('id')
                vars_[step['as']] = rid
                st.update({'role_id': rid})
                st['ok'] = rid is not None
            elif act == 'redis_del':
                out = redis_del([render(k) for k in step['keys']])
                st.update({'deleted': out})
                st['ok'] = True
            elif act == 'find_record':
                data = vars_.get(step['from']) or {}
                recs = []
                if isinstance(data, dict):
                    recs = data.get('records') or (data.get('data') or {}).get('records') or []
                val = render(step['value'])
                found = None
                for rec in recs:
                    if str(rec.get(step.get('field', 'name'))) == str(val):
                        found = rec
                        break
                rid = (found or {}).get(step.get('id_field', 'id'))
                vars_[step['as']] = rid
                st.update({'record': found, 'var': rid})
                st['ok'] = rid is not None
            elif act == 'sql_scalar':
                out = run_sql(render(step['sql']))
                val = out.splitlines()[0].split('\t')[0] if out.splitlines() else ''
                vars_[step['as']] = val
                st.update({'sql': render(step['sql']), 'value': val})
                st['ok'] = bool(val)
            elif act == 'try_bodies':
                attempts = []
                ok_body = None
                for b in render(step['bodies']):
                    r = req(render(step.get('method', 'POST')), render(step['path']), b, tokens.get(step.get('as', '')) or None)
                    attempts.append({'body': b, 'code': r.get('code'), 'msg': r.get('msg')})
                    if str(r.get('code')) == '0':
                        ok_body = b
                        break
                st.update({'attempts': attempts, 'ok_body': ok_body})
                st['ok'] = ok_body is not None
            elif act == 'sql':
                out = run_sql(render(step['sql']))
                st.update({'sql': render(step['sql']), 'output': out[:500]})
                st['ok'] = True
            elif act == 'sleep':
                time.sleep(float(step.get('seconds', 1)))
                st['ok'] = True
            else:
                st['ok'] = False
                st['error'] = 'unknown action'
        except Exception as e:
            st['ok'] = False
            st['error'] = str(e)[:300]
        results['steps'].append(st)
        print('PASS' if st.get('ok') else 'FAIL', phase, st.get('name'), st.get('code'), st.get('error', ''))
        return st
    try:
        for step in scen.get('steps', []):
            execute(step)
    finally:
        for step in scen.get('cleanup', []):
            execute(step, 'cleanup')
        results['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
        results['vars'] = {k: str(v)[:200] if not isinstance(v, (dict, list)) else v for (k, v) in vars_.items()}
        results['verdict'] = 'PASS' if all((s.get('ok') for s in results['steps'] if s['phase'] == 'main')) else 'FAIL'
        out = os.path.join(OUT_DIR, f'{name}.json')
        json.dump(results, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print('written:', out, 'verdict:', results['verdict'])
if __name__ == '__main__':
    sys.exit(main())
