"""统一环境配置加载器：configs/scan.local.yaml -> 进程环境变量。

外部项目（cesauto-api-test / ces_UI_auto）保持只读，不写入其配置文件。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import os
import re
import yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG = os.path.join(ROOT, 'configs', 'scan.local.yaml')
_ENV_RE = re.compile('\\$\\{([A-Za-z_][A-Za-z0-9_]*)\\}')

def config_path():
    return os.environ.get('GATE_SCAN_CONFIG') or DEFAULT_CONFIG

def _expand(value):
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ''), value)
    if isinstance(value, dict):
        return {k: _expand(v) for (k, v) in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value

def load(path=None):
    p = path or config_path()
    if not os.path.exists(p):
        raise FileNotFoundError('未找到环境配置：%s（请复制 configs/scan.example.yaml）' % p)
    with open(p, encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}
    return _expand(data)

def export_env(cfg=None):
    cfg = cfg or load()
    web = cfg.get('web') or {}
    accounts = cfg.get('accounts') or {}
    api = cfg.get('api') or {}
    ui = cfg.get('ui') or {}
    scan = cfg.get('scan') or {}
    env = {'GATE_BASE_URL': web.get('base_url', ''), 'SEC_BACKEND_USER': (accounts.get('admin') or {}).get('username', 'sysmanager'), 'SEC_BACKEND_PASS': (accounts.get('admin') or {}).get('password', ''), 'SEC_PREFLIGHT_USER': (accounts.get('preflight_admin') or {}).get('username', 'admin02'), 'SEC_PREFLIGHT_PASS': (accounts.get('preflight_admin') or {}).get('password', ''), 'SEC_IDOR_A_USER': (accounts.get('idor_a') or {}).get('username', ''), 'SEC_IDOR_A_PASS': (accounts.get('idor_a') or {}).get('password', ''), 'SEC_IDOR_B_USER': (accounts.get('idor_b') or {}).get('username', ''), 'SEC_IDOR_B_PASS': (accounts.get('idor_b') or {}).get('password', ''), 'SEC_OPEN_KEY': api.get('openapi_key', ''), 'SEC_OPEN_SECRET': api.get('openapi_secret', ''), 'GATE_APPSCAN_REPORT': scan.get('appscan_report', ''), 'GATE_WEAK_TEST_USERS': ','.join(accounts.get('weak_test_users') or []), 'GATE_LOGIN_TEST_USERS': ','.join(accounts.get('login_test_users') or []), 'SEC_WEAK_TEST_PASS': accounts.get('weak_test_password', ''), 'SEC_LOGIN_TEST_PASS': accounts.get('login_test_password', ''), 'UIAUTO_BASE_URL': web.get('base_url', ''), 'UIAUTO_USERNAME': (accounts.get('admin') or {}).get('username', ''), 'UIAUTO_PASSWORD': (accounts.get('admin') or {}).get('password', ''), 'UIAUTO_CHROMEDRIVER_PATH': ui.get('chromedriver', ''), 'GATE_OAST_DOMAIN': scan.get('oast_domain', '')}
    if scan.get('allow_write_chain'):
        env['ALLOW_WRITE_CHAIN'] = '1'
    for (k, v) in env.items():
        if v:
            os.environ[k] = str(v)
    os.environ['GATE_SCAN_CONFIG'] = config_path()
    from runner.public_config import FIELDS, env as get_public_env
    for name in FIELDS:
        value = get_public_env(name)
        if value:
            os.environ[name] = str(value)
    return env
