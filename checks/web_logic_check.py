"""应用安全：业务逻辑配置驱动自动化。

configs/web_automation.yaml -> business_logic.flows:
  - name: 注册覆盖
    method: POST
    path: /api/register
    headers: {...}
    baseline: {userName: zhangsan, ...}
    variant:  {userName: "zhangsan ", ...}
    success_codes: [0, "0"]
    cleanup:
      - {method: POST, path: /api/user/del, json: {...}}
未配置时只登记入口，不做写操作。
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

def token(cfg):
    t = cfg.get('token_data') or {}
    if t.get('file'):
        p = os.path.join(gc.ROOT, t['file'])
        if os.path.exists(p):
            return open(p, encoding='utf-8').read().strip()
    if t.get('env'):
        return os.environ.get(t['env'], '')
    return ''

def send(case, auth):
    headers = dict(case.get('headers') or {})
    headers.update(auth)
    try:
        r = requests.request(case.get('method', 'POST'), BASE + case['path'], headers=headers, json=case.get('json'), params=case.get('params'), timeout=15, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {}
        return {'http': r.status_code, 'code': j.get('code') or j.get('resCode'), 'len': len(r.text or ''), 'body': (r.text or '')[:300]}
    except Exception as e:
        return {'error': str(e)[:100]}

def ok(res, codes):
    codes = set((str(x) for x in codes or [0, '0']))
    if res.get('code') is not None:
        return str(res.get('code')) in codes
    return res.get('http') in (200, 201)

def main():
    root = load_cfg()
    cfg = root.get('business_logic') or {}
    flows = cfg.get('flows') or []
    if not cfg.get('enabled') or not flows:
        gc.emit('web_logic_check', 'application', 'PASS', [gc.finding('WEB-LOGIC-MANUAL', 'info', '业务逻辑未配置自动化流程；请填写 configs/web_automation.yaml 的 business_logic.flows', evidence='enabled=false')], summary='business logic not configured')
        return
    auth = web_auth.headers(root)
    run_id = time.strftime('%Y%m%d%H%M%S')

    def sub(v):
        if isinstance(v, dict):
            return {k: sub(x) for (k, x) in v.items()}
        if isinstance(v, list):
            return [sub(x) for x in v]
        if isinstance(v, str):
            return v.replace('${run_id}', run_id)
        return v
    (findings, results) = ([], [])
    for f in flows:
        base = send({'method': f.get('method'), 'path': f['path'], 'headers': f.get('headers'), 'json': sub(f.get('baseline', {})), 'params': f.get('params')}, auth)
        var = send({'method': f.get('method'), 'path': f['path'], 'headers': f.get('headers'), 'json': sub(f.get('variant', {})), 'params': f.get('params')}, auth)
        results.append({'name': f.get('name'), 'baseline': base, 'variant': var})
        if ok(base, f.get('success_codes')) and ok(var, f.get('success_codes')):
            findings.append(gc.finding('WEB-LOGIC-BYPASS', 'medium', f"业务逻辑：{f.get('name')} baseline/variant 均成功", evidence=json.dumps(results[-1], ensure_ascii=False)[:500], remediation='服务端校验业务唯一性/步骤/归属'))
        for c in f.get('cleanup') or []:
            try:
                requests.request(c.get('method', 'POST'), BASE + c['path'], headers={**(c.get('headers') or {}), **auth}, json=sub(c.get('json')), timeout=10, verify=False)
            except Exception:
                pass
    gc.emit('web_logic_check', 'application', 'PASS', findings, summary=json.dumps({'flows': results}, ensure_ascii=False)[:800])
if __name__ == '__main__':
    main()
