"""应用安全：历史 RCE 写链验证（配置驱动、默认关闭、仅授权隔离环境）。

configs/web_automation.yaml -> rce_write_chain
- enabled: false（默认关闭）
- require_env: ALLOW_WRITE_CHAIN（必须显式设置环境变量才执行）
步骤：GetNodeInfo -> 添加测试管理员 -> 登录 -> 上传测试标记文件 -> cleanup
只上传无害标记文件，不写真实 webshell；用户需提供各步骤请求配置。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import hashlib
import json
import os
import re
import time
import requests
import urllib3
import yaml
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

def req(step, **kw):
    try:
        r = requests.request(step.get('method', 'POST'), BASE + step['path'], headers=step.get('headers') or {}, params=step.get('params'), data=step.get('data'), json=step.get('json'), files=kw.get('files'), timeout=15, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {}
        return {'http': r.status_code, 'code': j.get('code') or j.get('resCode'), 'body': (r.text or '')[:500], 'json': j}
    except Exception as e:
        return {'error': str(e)[:120]}

def main():
    cfg = load_cfg().get('rce_write_chain') or {}
    if not cfg.get('enabled'):
        gc.emit('rce_write_chain', 'application', 'PASS', [gc.finding('RCE-CHAIN-DISABLED', 'info', 'RCE 写链验证未启用（默认关闭，需授权隔离环境）')], summary='disabled')
        return
    need = cfg.get('require_env') or 'ALLOW_WRITE_CHAIN'
    allow_write = os.environ.get(need) == '1'
    steps = cfg.get('steps') or {}
    if not steps.get('get_node') or not steps.get('add_admin'):
        gc.emit('rce_write_chain', 'application', 'BLOCKED', [], blocked_reason='rce_write_chain.steps 未配置')
        return
    username = 'secauto_chain_' + str(int(time.time()))
    password = 'SecautoChain#2026'
    md5 = hashlib.md5(password.encode()).hexdigest().upper()
    (node_id, evidence) = ('', {})
    r = req(steps['get_node'])
    evidence['get_node'] = r
    m = re.search(str(steps['get_node'].get('node_regex', 'nodeID[^\\d]{0,20}(\\d+)')), r.get('body', ''), re.I)
    if not m:
        gc.emit('rce_write_chain', 'application', 'PASS', [], summary=json.dumps({'note': 'GetNodeInfo 未返回 nodeID（可能已修复）', 'evidence': evidence}, ensure_ascii=False)[:800])
        return
    node_id = m.group(1)
    if not allow_write:
        gc.emit('rce_write_chain', 'application', 'PASS', [gc.finding('RCE-CHAIN-READONLY', 'high', '历史 GetNodeInfo 仍可用（未执行写链；设置 ALLOW_WRITE_CHAIN=1 才验证写链）', evidence=json.dumps(evidence['get_node'], ensure_ascii=False)[:400], remediation='升级版本/接口鉴权')], summary=json.dumps({'node_id': node_id, 'write': False}, ensure_ascii=False))
        return
    body = str(steps['add_admin'].get('template', '')).replace('{node_id}', node_id).replace('{username}', username).replace('{password_md5}', md5)
    r = req(steps['add_admin'], data=body)
    evidence['add_admin'] = {k: v for (k, v) in r.items() if k != 'json'}
    findings = []
    if r.get('http') in (200, 201) and str(r.get('code')) in ('0', 'None'):
        findings.append(gc.finding('RCE-CHAIN-ADD-ADMIN', 'critical', '历史 RCE 链：未授权添加测试管理员成功', evidence=json.dumps(evidence['add_admin'], ensure_ascii=False)[:400], remediation='升级版本；接口鉴权；删除测试账号'))
        login = steps.get('login') or {}
        if login:
            body = {k: str(v).replace('{username}', username).replace('{password}', password) for (k, v) in (login.get('json') or {}).items()}
            lr = req({'method': login.get('method', 'POST'), 'path': login['path'], 'headers': login.get('headers'), 'json': body, 'params': login.get('params')})
            evidence['login'] = {k: v for (k, v) in lr.items() if k != 'json'}
            tok = lr.get('json', {}).get('access_token', '') if isinstance(lr.get('json'), dict) else ''
            if tok:
                findings.append(gc.finding('RCE-CHAIN-LOGIN', 'critical', '历史 RCE 链：测试管理员登录成功', evidence=tok[:60]))
                up = steps.get('upload') or {}
                if up:
                    url = BASE + up['path']
                    headers = dict(up.get('headers') or {})
                    headers.setdefault('Authorization', 'Bearer ' + tok)
                    try:
                        r = requests.post(url, headers=headers, files={'file': ('secauto_marker.txt', b'secauto benign upload marker', 'text/plain')}, timeout=15, verify=False)
                        ok = r.status_code in (200, 201)
                        evidence['upload'] = {'http': r.status_code, 'len': len(r.text or '')}
                        if ok:
                            findings.append(gc.finding('RCE-CHAIN-UPLOAD', 'high', '历史 RCE 链：测试标记文件上传被接受', evidence=json.dumps(evidence['upload'], ensure_ascii=False)))
                    except Exception as e:
                        evidence['upload'] = {'error': str(e)[:100]}
    for c in cfg.get('cleanup') or []:
        try:
            cc = dict(c)
            cc['json'] = json.loads(json.dumps(c.get('json') or {}).replace('{username}', username).replace('{password}', password).replace('{password_md5}', md5).replace('{node_id}', node_id))
            req(cc)
        except Exception:
            pass
    gc.emit('rce_write_chain', 'application', 'PASS', findings, summary=json.dumps(evidence, ensure_ascii=False)[:1000])
if __name__ == '__main__':
    main()
