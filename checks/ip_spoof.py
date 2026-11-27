"""应用安全：登录/操作 IP 伪造检查（X-Forwarded-For / X-Real-IP / Forwarded）。

客户历史报告：抓包添加 X-Forwarded-For 修改登录/操作 IP。
本检查：带伪造 IP 请求，若响应回显/日志字段反映伪造值，或与基准响应存在差异，则记录。
"""
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
try:
    from checks import web_auth
except ImportError:
    import web_auth
urllib3.disable_warnings()
BASE = gc.base_url()
FAKE = '203.0.113.77'
HEADERS = ['X-Forwarded-For', 'X-Real-IP', 'Forwarded', 'X-Client-IP']
PATHS = ['/api/v1/user/list', '/serv/v1/index/info', '/serv/v1/sys/setting/logger']

def main():
    root = {}
    headers_auth = web_auth.headers({'auth': {'type': 'openapi', 'config_ini': 'configured-path'}})
    (findings, probes) = ([], [])
    for path in PATHS:
        baseline = None
        try:
            r = requests.get(BASE + path, headers={**headers_auth, 'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=False)
            baseline = {'http': r.status_code, 'len': len(r.text or ''), 'body': (r.text or '')[:500]}
        except Exception:
            pass
        for hname in HEADERS:
            try:
                r = requests.get(BASE + path, headers={**headers_auth, 'User-Agent': 'Mozilla/5.0', hname: FAKE}, timeout=10, verify=False)
                body = r.text or ''
                probes.append({'path': path, 'header': hname, 'http': r.status_code, 'reflected': FAKE in body})
                if FAKE in body:
                    findings.append(gc.finding('IP-SPOOF-REFLECTED', 'medium', f'伪造 IP 被响应回显：{path} {hname}', evidence=body[:300], remediation='不要信任客户端 IP 头；使用可信代理链'))
                if baseline and r.status_code == baseline['http'] and (abs(len(body) - baseline['len']) > 100):
                    findings.append(gc.finding('IP-SPOOF-DIFF', 'low', f'伪造 IP 导致响应差异：{path} {hname}', evidence=json.dumps(probes[-1], ensure_ascii=False), remediation='校验可信代理/日志取真实 IP'))
            except Exception:
                pass
    gc.emit('ip_spoof', 'application', 'PASS', findings, summary=json.dumps({'fake_ip': FAKE, 'probes': probes}, ensure_ascii=False)[:800])
if __name__ == '__main__':
    main()
