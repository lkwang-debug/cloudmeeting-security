"""应用安全：敏感端点/接口文档暴露（Actuator/Swagger/.git 等，AppScan 常见项）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()
PATHS = ['/actuator', '/actuator/env', '/actuator/health', '/v2/api-docs', '/v3/api-docs', '/swagger-ui.html', '/swagger-ui/index.html', '/doc.html', '/swagger-resources', '/.git/config', '/.env', '/apis/', '/robots.txt', '/static/img/config.js', '/config.js', '/backup.zip', '/fmapi/servers/addresses']

def main():
    findings = []
    tested = []
    for path in PATHS:
        try:
            r = requests.get(BASE + path, timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        except Exception:
            continue
        body = (r.text or '')[:300]
        tested.append({'path': path, 'http': r.status_code, 'len': len(body)})
        if r.status_code != 200 or not body:
            continue
        low = body.lower()
        if path.startswith('/.git') or path == '/.env' or path == '/backup.zip':
            findings.append(gc.finding('EXPOSE-SECRET-FILE', 'high', f'敏感文件暴露：{path}', evidence=body[:200], remediation='禁止访问 .git/.env/备份'))
        elif 'index of /' in low or 'directory listing' in low:
            findings.append(gc.finding('EXPOSE-DIR-LISTING', 'medium', f'目录列表暴露：{path}', evidence=body[:200], remediation='关闭 autoindex'))
        elif path == '/robots.txt':
            findings.append(gc.finding('EXPOSE-ROBOTS', 'low', f'robots.txt 可读：{path}', evidence=body[:200], remediation='避免泄露敏感路径'))
        elif path in ('/static/img/config.js', '/config.js'):
            sev = 'high' if any((k in low for k in ('key', 'secret', 'password', 'appkey', 'ftp', 'oauth', 'client'))) else 'medium'
            findings.append(gc.finding('EXPOSE-CONFIG-JS', sev, f'前端配置文件暴露：{path}', evidence=body[:200], remediation='移除敏感配置/限制访问'))
        elif path == '/fmapi/servers/addresses':
            if any((k in low for k in ('server', 'address', 'ftp', 'appkey'))):
                findings.append(gc.finding('EXPOSE-FMAPI', 'high', 'fmapi/servers/addresses 未授权暴露', evidence=body[:200], remediation='接口鉴权/移除凭据'))
        else:
            findings.append(gc.finding('EXPOSE-API-DOC', 'medium', f'接口/监控文档暴露：{path}', evidence=body[:200], remediation='生产关闭/鉴权 Actuator/Swagger'))
    gc.emit('endpoint_exposure', 'application', 'PASS', findings, summary=json.dumps({'probes': tested}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
