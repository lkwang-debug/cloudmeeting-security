"""门禁检查公共库：证据 JSON 输出与规范化 finding。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import sys
import threading
import time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EVIDENCE = os.path.join(ROOT, 'reports', 'final', 'gate', 'evidence')
EVIDENCE_DIR = os.environ.get('GATE_EVIDENCE_DIR') or DEFAULT_EVIDENCE
HTTP_EVIDENCE = os.environ.get('GATE_HTTP_EVIDENCE', '0') == '1'
_HTTP_LOCK = threading.Lock()
_HTTP_SEQ = {'n': 0}
_SENSITIVE = re.compile('(?i)(authorization|token|cookie|password|passwd|secret|set-cookie)')

def _safe_headers(h):
    out = {}
    for (k, v) in dict(h or {}).items():
        out[str(k)] = '***' if _SENSITIVE.search(str(k)) else str(v)[:300]
    return out

def _check_id():
    env = os.environ.get('GATE_CHECK_ID')
    if env:
        return env
    return os.path.basename(sys.argv[0]).replace('.py', '') or 'unknown'

def _record(method, url, kwargs, resp):
    try:
        with _HTTP_LOCK:
            _HTTP_SEQ['n'] += 1
            seq = _HTTP_SEQ['n']
        d = os.path.join(EVIDENCE_DIR, 'http', _check_id())
        os.makedirs(d, exist_ok=True)
        body = kwargs.get('json')
        if body is None:
            body = kwargs.get('data')
        if isinstance(body, dict):
            body = {k: '***' if _SENSITIVE.search(str(k)) else v for (k, v) in body.items()}
        rec = {'seq': seq, 'time': time.strftime('%Y-%m-%dT%H:%M:%S'), 'request': {'method': str(method).upper(), 'url': str(url), 'params': kwargs.get('params'), 'headers': _safe_headers(kwargs.get('headers')), 'body': body, 'files': [f[0] if isinstance(f, (tuple, list)) else str(f) for f in kwargs.get('files') or []]}, 'response': {'status': getattr(resp, 'status_code', None), 'headers': _safe_headers(getattr(resp, 'headers', {})), 'body': (getattr(resp, 'text', '') or '')[:6000], 'elapsed_ms': round((getattr(resp, 'elapsed', None).total_seconds() if getattr(resp, 'elapsed', None) else 0) * 1000)}}
        with open(os.path.join(d, 'req_%04d.json' % seq), 'w', encoding='utf-8') as f:
            json.dump(rec, f, ensure_ascii=False, indent=1)
    except Exception:
        pass

def _install_http_recorder():
    if not HTTP_EVIDENCE:
        return
    try:
        import requests
        if getattr(requests.Session.request, '_gate_recorded', False):
            return
        orig = requests.Session.request

        def wrapped(self, method, url, **kwargs):
            resp = orig(self, method, url, **kwargs)
            _record(method, url, kwargs, resp)
            return resp
        wrapped._gate_recorded = True
        requests.Session.request = wrapped
    except Exception:
        pass

def screenshot(page, check_id, name):
    """保存浏览器截图到 evidence/screenshots/<check>/，返回路径。"""
    try:
        d = os.path.join(EVIDENCE_DIR, 'screenshots', check_id)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, re.sub('[^0-9A-Za-z_-]+', '_', name)[:80] + '.png')
        page.screenshot(path=path, full_page=True)
        return path
    except Exception:
        return ''
_install_http_recorder()

def base_url():
    return os.environ.get('GATE_BASE_URL') or _pub.target()

def evidence_path(check_id):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    return os.path.join(EVIDENCE_DIR, check_id + '.json')

def finding(fid, severity, title, evidence='', remediation='', confidence='medium'):
    return {'id': fid, 'severity': severity, 'title': title, 'evidence': evidence, 'remediation': remediation, 'confidence': confidence}

def emit(check_id, category, status, findings=None, summary='', blocked_reason=''):
    """status: PASS / FAIL / BLOCKED / ERROR"""
    payload = {'check_id': check_id, 'category': category, 'status': status, 'summary': summary, 'blocked_reason': blocked_reason, 'findings': findings or [], 'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'evidence_dir': EVIDENCE_DIR}
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    with open(evidence_path(check_id), 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    print(json.dumps({'check_id': check_id, 'status': status, 'findings': len(payload['findings']), 'blocked': blocked_reason[:80]}, ensure_ascii=False))
    return payload

def endpoint_keys():
    """从知识库取真实采集的接口参数（用于反射/下载/注入类检查）。"""
    path = os.environ.get('GATE_ENDPOINTS_FILE') or os.path.join(ROOT, 'knowledge', 'backend_endpoints.json')
    if not os.path.exists(path):
        return []
    data = json.load(open(path, encoding='utf-8'))
    return data.get('endpoints') or []

def all_endpoints():
    path = os.environ.get('GATE_ALL_ENDPOINTS_FILE') or os.path.join(ROOT, 'knowledge', 'all_backend_endpoints.json')
    if not os.path.exists(path):
        return []
    data = json.load(open(path, encoding='utf-8'))
    return data.get('endpoints') or []

def token(name='admin02'):
    env_key = 'GATE_TOKEN_' + name.upper()
    if os.environ.get(env_key):
        return os.environ[env_key]
    p = os.path.join(ROOT, 'evidence', 'tokens', f'{name}.txt')
    return open(p, encoding='utf-8').read().strip() if os.path.exists(p) else ''
