"""应用安全：CSRF 配置驱动自动化。

人工在 configs/web_automation.yaml 填写：
- 登录/Token 获取方式
- 一个状态变更请求的 baseline（带 Origin/Referer/CSRF token）
- replay 时去掉的 Header/body 字段
若未配置，则输出信息项，不伪造结果。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
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

def send(case, auth, strip_headers=None, strip_body_keys=None):
    method = case.get('method', 'POST')
    url = BASE + case['path']
    headers = dict(case.get('headers') or {})
    body = dict(case.get('json') or {})
    for k in strip_headers or []:
        headers.pop(k, None)
    for k in strip_body_keys or []:
        body.pop(k, None)
    headers.update(auth)
    try:
        r = requests.request(method, url, headers=headers, json=body if body or method != 'GET' else None, params=case.get('params'), timeout=15, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {}
        return {'http': r.status_code, 'code': j.get('code') or j.get('resCode'), 'len': len(r.text or ''), 'body': (r.text or '')[:300]}
    except Exception as e:
        return {'error': str(e)[:120]}

def main():
    root = load_cfg()
    cfg = root.get('csrf') or {}
    if not cfg.get('enabled'):
        gc.emit('csrf_check', 'application', 'PASS', [gc.finding('CSRF-MANUAL', 'info', 'CSRF 未配置自动化用例；请填写 configs/web_automation.yaml 的 csrf 段', evidence='enabled=false')], summary='csrf not configured')
        return
    auth = web_auth.headers(root)
    baseline_case = cfg.get('baseline') or {}
    replay_case = cfg.get('replay') or baseline_case
    if not baseline_case.get('path'):
        gc.emit('csrf_check', 'application', 'BLOCKED', [], blocked_reason='csrf.baseline.path 未配置')
        return
    b = send(baseline_case, auth)
    r = send(replay_case, auth, cfg.get('strip_headers') or ['Origin', 'Referer'], cfg.get('strip_body_keys') or [])
    ok_codes = set((str(x) for x in cfg.get('success_codes') or [0, '0', 200]))
    b_ok = str(b.get('code')) in ok_codes or b.get('http') in (200, 201)
    r_ok = str(r.get('code')) in ok_codes or r.get('http') in (200, 201)
    findings = []
    if 'Authorization' in auth:
        gc.emit('csrf_check', 'application', 'PASS', [gc.finding('CSRF-MANUAL', 'info', '目标 API 使用 Authorization 头，传统 CSRF 不适用；如需验证请配置 Cookie 会话/UI 流程', evidence=json.dumps({'baseline': b, 'replay': r}, ensure_ascii=False)[:400])], summary='header-auth; csrf not applicable')
        return
    if b_ok and r_ok and b.get('len') and (abs(b.get('len', 0) - r.get('len', 0)) < 80):
        findings.append(gc.finding('CSRF-CONFIRMED', 'high', 'CSRF 自动化验证：去掉 Origin/Referer/CSRF token 后请求仍成功', evidence=json.dumps({'baseline': b, 'replay': r}, ensure_ascii=False)[:500], remediation='校验 Origin/Referer/CSRF token；SameSite'))
    gc.emit('csrf_check', 'application', 'PASS', findings, summary=json.dumps({'baseline': b, 'replay': r}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
