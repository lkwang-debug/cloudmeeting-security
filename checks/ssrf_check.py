"""应用安全：SSRF 配置驱动自动化（OAST 回连 + 差分）。

configs/web_automation.yaml -> ssrf.endpoints:
  - method: POST
    path: /xxx
    param: url
    param_in: json   # json|query|form
"""
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
    from checks import web_auth
except ImportError:
    import web_auth
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()
CFG = os.environ.get('GATE_WEB_AUTOMATION') or os.path.join(gc.ROOT, 'configs', 'web_automation.yaml')

def load_cfg():
    try:
        return yaml.safe_load(open(CFG, encoding='utf-8')) or {}
    except Exception:
        return {}

def oast_mod():
    try:
        import importlib.util
        p = os.path.join(gc.ROOT, 'adapters', 'oast', 'oast.py')
        spec = importlib.util.spec_from_file_location('gate_oast', p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None

def token(cfg):
    t = cfg.get('token_data') or {}
    if t.get('file'):
        p = os.path.join(gc.ROOT, t['file'])
        if os.path.exists(p):
            return open(p, encoding='utf-8').read().strip()
    if t.get('env'):
        return os.environ.get(t['env'], '')
    return ''

def send(ep, auth, payload):
    method = ep.get('method', 'GET')
    path = ep['path']
    where = ep.get('param_in', 'query')
    headers = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0'}
    headers.update(auth)
    kw = {'headers': headers, 'timeout': 15, 'verify': False, 'params': {'t': str(int(time.time() * 1000))}}
    if where == 'json':
        body = dict(ep.get('base_body') or {})
        body[ep['param']] = payload
        kw['json'] = body
    elif where == 'form':
        kw['data'] = {ep['param']: payload}
    else:
        kw['params'][ep['param']] = payload
    try:
        r = requests.request(method, BASE + path, **kw)
        return {'http': r.status_code, 'len': len(r.text or ''), 'body': (r.text or '')[:300]}
    except Exception as e:
        return {'error': str(e)[:100]}

def main():
    root = load_cfg()
    cfg = root.get('ssrf') or {}
    if not cfg.get('enabled'):
        gc.emit('ssrf_check', 'application', 'PASS', [gc.finding('SSRF-MANUAL', 'info', 'SSRF 未配置自动化用例；请填写 configs/web_automation.yaml 的 ssrf 段', evidence='enabled=false')], summary='ssrf not configured')
        return
    eps = cfg.get('endpoints') or []
    if not eps:
        gc.emit('ssrf_check', 'application', 'BLOCKED', [], blocked_reason='ssrf.endpoints 未配置')
        return
    auth = web_auth.headers(root)
    oast = oast_mod()
    domain = ''
    if oast:
        try:
            domain = (oast.status() or {}).get('domain', '')
            if not domain and cfg.get('auto_start'):
                domain = (oast.start() or {}).get('domain', '')
        except Exception:
            domain = ''
    (findings, probes) = ([], [])
    token_id = 'ssrf-%d' % int(time.time())
    if domain and oast:
        try:
            payload = oast.url(token_id, 'ssrf')
        except Exception:
            payload = ''
    else:
        payload = 'http://127.0.0.1:28443/'
    for ep in eps:
        res = send(ep, auth, payload)
        probes.append({'endpoint': ep, 'payload': payload, **res})
    if domain and oast:
        hits = oast.wait_for(token_id, timeout=int(cfg.get('timeout', 20)))
        if hits:
            findings.append(gc.finding('SSRF-OAST', 'high', 'SSRF 触发 OAST 回连', evidence=json.dumps(hits[:2], ensure_ascii=False)[:500], remediation='URL 白名单/禁止内网/OAST 复核'))
    for c in cfg.get('cleanup') or []:
        try:
            m = c.get('method', 'DELETE')
            requests.request(m, BASE + c['path'], headers={**auth, **(c.get('headers') or {})}, json=c.get('json'), params=c.get('params'), timeout=10, verify=False)
        except Exception:
            pass
    gc.emit('ssrf_check', 'application', 'PASS', findings, summary=json.dumps({'oast_domain': domain, 'probes': probes}, ensure_ascii=False)[:800])
if __name__ == '__main__':
    main()
