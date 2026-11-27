"""Portable configuration access for the publication copy.

No credentials or real deployment endpoints are bundled. Environment variables
take precedence over configs/scan.local.yaml. Values are never logged here.
"""
import os
import shlex
from pathlib import Path
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {
    'GATE_BASE_URL': 'web.base_url', 'SEC_TARGET': 'web.base_url',
    'SEC_SSH_HOST': 'hosts.app_ip', 'SEC_SSH_USER': 'hosts.ssh_user',
    'SEC_SSH_PASSWORD': 'hosts.ssh_pass', 'SEC_SSH_PASS': 'hosts.ssh_pass',
    'SEC_DB_HOST': 'hosts.db_host', 'SEC_DB_USER': 'hosts.db_user',
    'SEC_REDIS_HOST': 'hosts.redis_host', 'SEC_DB_PASSWORD': 'hosts.db_pass',
    'SEC_REDIS_PASSWORD': 'hosts.redis_pass',
    'SEC_BACKEND_USER': 'accounts.admin.username', 'SEC_BACKEND_PASS': 'accounts.admin.password',
    'SEC_IDOR_A_USER': 'accounts.idor_a.username', 'SEC_IDOR_A_PASS': 'accounts.idor_a.password',
    'SEC_IDOR_B_USER': 'accounts.idor_b.username', 'SEC_IDOR_B_PASS': 'accounts.idor_b.password',
    'SEC_OPEN_KEY': 'api.openapi_key', 'SEC_OPEN_SECRET': 'api.openapi_secret',
    'SEC_CLIENT_ID': 'api.oauth_client_id', 'SEC_CLIENT_SECRET': 'api.oauth_client_secret',
}


def config():
    p = Path(os.environ.get('GATE_SCAN_CONFIG') or ROOT / 'configs/scan.local.yaml')
    if not p.is_file():
        return {}
    return yaml.safe_load(p.read_text(encoding='utf-8-sig')) or {}


def env(name, default=''):
    if name in os.environ:
        return os.environ[name]
    path = FIELDS.get(name)
    if not path:
        return default
    value = config()
    for part in path.split('.'):
        value = value.get(part) if isinstance(value, dict) else None
    if isinstance(value, str):
        import re
        value = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}',
                       lambda m: os.environ.get(m.group(1), ''), value)
    return value if value is not None and value != '' else default


def target():
    return str(env('GATE_BASE_URL', 'https://example.test:28443')).rstrip('/')


def web_host():
    return urlsplit(target()).hostname or 'example.test'


def shell(name):
    value = env(name)
    if not value:
        raise ValueError('Required local configuration is missing: ' + name)
    return shlex.quote(str(value))
