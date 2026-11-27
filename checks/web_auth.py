"""Web 自动化鉴权辅助：OpenAPI key/secret 或静态 token。

优先读取 scan.local.yaml 的 api.openapi_key/secret 或环境变量 SEC_OPEN_KEY/SECRET；
兼容旧的 web_automation.yaml auth.config_ini 方式。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import configparser
import hashlib
import os
import time
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc

def _openapi_headers(key, secret):
    if not key or not secret:
        return {}
    ts = str(round(time.time() * 1000))
    h = base64.b64encode(b'{"alg": "SHA256"}').decode()
    p2 = base64.b64encode(('{"key": "%s", "timestamp": %s}' % (key, ts)).encode()).decode()
    sig = hashlib.sha256((h + p2 + secret).encode()).hexdigest()
    return {'Authorization': f'{h}.{p2}.{sig}'}

def _from_ini(ini_path):
    p = os.environ.get('GATE_API_CONFIG_INI') or ini_path
    if not p or not os.path.exists(p):
        return {}
    cp = configparser.ConfigParser()
    cp.read(p, encoding='utf-8')
    try:
        return _openapi_headers(cp.get('auth', 'key'), cp.get('auth', 'secret'))
    except Exception:
        return {}

def headers(cfg):
    cfg = cfg or {}
    api = cfg.get('api') or {}
    key = os.environ.get('SEC_OPEN_KEY') or api.get('openapi_key')
    secret = os.environ.get('SEC_OPEN_SECRET') or api.get('openapi_secret')
    if key and secret:
        return _openapi_headers(key, secret)
    auth = cfg.get('auth') or {}
    typ = auth.get('type', 'token')
    if typ == 'openapi':
        key = os.environ.get('SEC_OPEN_KEY') or auth.get('key')
        secret = os.environ.get('SEC_OPEN_SECRET') or auth.get('secret')
        if key and secret:
            return _openapi_headers(key, secret)
        return _from_ini(auth.get('config_ini', ''))
    if typ == 'token':
        tok = ''
        if auth.get('env'):
            tok = os.environ.get(auth['env'], '')
        elif auth.get('file'):
            p = os.path.join(gc.ROOT, auth['file'])
            if os.path.exists(p):
                tok = open(p, encoding='utf-8').read().strip()
        if not tok:
            return {}
        return {auth.get('header', 'token'): tok}
    return {}

def merge(cfg, extra=None):
    h = dict(extra or {})
    h.update(headers(cfg))
    return h
