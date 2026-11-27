"""切环境预检：检查配置完整性、Web/OpenAPI、双身份录制数据、测试数据/驱动准备情况。

输出 reports/final/ENV_READINESS.md；有阻断项返回 1。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import subprocess
import sys
import requests
import urllib3
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from runner import env_config
urllib3.disable_warnings()
OUT = os.path.join(ROOT, 'reports', 'final', 'ENV_READINESS.md')
rows = []

def add(level, item, detail):
    rows.append({'level': level, 'item': item, 'detail': detail})
    print('[%s] %s %s' % (level, item, detail))

def required(cfg, path, label):
    cur = cfg
    for key in path.split('.'):
        cur = (cur or {}).get(key) if isinstance(cur, dict) else None
    if not cur:
        add('FAIL', label, '未配置 %s' % path)
        return False
    low = label.lower() + path.lower()
    if any((x in low for x in ('password', '密码', 'secret', 'key'))):
        add('OK', label, '***已配置***')
    else:
        add('OK', label, str(cur)[:80])
    return True

def main():
    cfg = env_config.load()
    env_config.export_env(cfg)
    ok = True
    for (path, label) in [('env.name', '环境名称'), ('web.base_url', 'Web 地址'), ('accounts.admin.username', '管理员账号'), ('accounts.admin.password', '管理员密码'), ('accounts.idor_a.username', 'IDOR A 账号'), ('accounts.idor_b.username', 'IDOR B 账号'), ('api.openapi_key', 'OpenAPI key'), ('api.openapi_secret', 'OpenAPI secret'), ('report.customer', '报告客户名')]:
        ok = required(cfg, path, label) and ok
    if (cfg.get('accounts') or {}).get('idor_a', {}).get('depart_id') == (cfg.get('accounts') or {}).get('idor_b', {}).get('depart_id'):
        add('FAIL', 'IDOR 部门', 'A/B 部门相同，无法做水平越权')
        ok = False
    else:
        add('OK', 'IDOR 部门', 'A/B 部门不同')
    if not ok:
        print('Missing required configuration; no target requests sent.')
        return 1
    base = (cfg.get('web') or {}).get('base_url', '').rstrip('/')
    try:
        r = requests.get(base + '/', timeout=15, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        add('OK' if r.status_code < 500 else 'FAIL', 'Web 可达', 'HTTP %s' % r.status_code)
        ok = ok and r.status_code < 500
    except Exception as e:
        add('FAIL', 'Web 可达', str(e)[:120])
        ok = False
    api = cfg.get('api') or {}
    h = {'Origin': base, 'Referer': base + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    try:
        from checks import web_auth
        h.update(web_auth.headers(cfg))
        r = requests.post(base + '/api/v1/user/list', headers=h, json={'pageNumber': 1, 'pageSize': 1}, timeout=15, verify=False)
        add('OK' if r.json().get('code') == '0' else 'FAIL', 'OpenAPI 鉴权', 'code=%s' % r.json().get('code'))
        ok = ok and r.json().get('code') == '0'
    except Exception as e:
        add('FAIL', 'OpenAPI 鉴权', str(e)[:120])
        ok = False
    rec_mode = (cfg.get('recording') or {}).get('mode', 'auto')
    if rec_mode == 'auto':
        for label in ('idor_a', 'idor_b'):
            acc = (cfg.get('accounts') or {}).get(label) or {}
            uname = acc.get('username', '')
            try:
                r = requests.post(base + '/api/v1/user/list', headers=h, json={'searchKey': uname, 'searchType': 0, 'pageSize': 10}, timeout=15, verify=False)
                recs = (r.json().get('data') or {}).get('records') or []
                uid = next((x.get('userId') for x in recs if x.get('userName') == uname), None)
                if not uid:
                    add('FAIL', '录制数据-%s' % uname, '未找到用户 ID')
                    ok = False
                    continue
                r = requests.get(base + '/api/v1/room/record-summaries', headers=h, params={'userId': uid, 'pageNumber': 1, 'pageSize': 5}, timeout=15, verify=False)
                rrecs = (r.json().get('data') or {}).get('records') or []
                add('OK' if rrecs else 'WARN', '录制数据-%s' % uname, '找到 %d 条录制' % len(rrecs))
                if not rrecs:
                    add('WARN', '录制 IDOR', '%s 无录制，录制/会议矩阵将跳过' % uname)
            except Exception as e:
                add('WARN', '录制数据-%s' % uname, str(e)[:100])
    else:
        missing = [k for k in ('group_id_a', 'group_id_b', 'room_id_a', 'room_id_b') if not (cfg.get('recording') or {}).get(k)]
        add('OK' if not missing else 'WARN', '录制 manual 模式', '缺: %s' % (missing or '无'))
    ds = cfg.get('data_strategy') or {}
    if not (ds.get('auto_create') or {}).get('room'):
        if not (ds.get('manual') or {}).get('room_id_a'):
            add('WARN', '手工会议室', 'auto_create.room=false 且未填 manual.room_id_a')
    ui = cfg.get('ui') or {}
    cd = ui.get('chromedriver', '')
    if cd and (not os.path.exists(cd)):
        add('WARN', 'Chromedriver', '路径不存在：%s' % cd)
    else:
        add('OK' if cd else 'WARN', 'Chromedriver', cd or '未配置')
    add('OK' if (cfg.get('scan') or {}).get('oast_domain') else 'WARN', 'OAST domain', (cfg.get('scan') or {}).get('oast_domain') or '未配置，SSRF 仅做差分')
    appscan = (cfg.get('scan') or {}).get('appscan_report', '')
    add('OK' if not appscan or os.path.exists(appscan) else 'WARN', 'AppScan 报告', appscan or '未配置')
    lines = ['# 环境准备检查（ENV_READINESS）', '', '配置：`%s`' % env_config.config_path(), '', '| 状态 | 项目 | 说明 |', '|---|---|---|']
    for r in rows:
        lines.append('| %s | %s | %s |' % (r['level'], r['item'], r['detail'].replace('|', '\\|')))
    lines += ['', '结论：%s' % ('通过' if ok else '存在阻断项，请先修复 FAIL 项')]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    print('readiness: %s' % OUT)
    return 0 if ok else 1
if __name__ == '__main__':
    sys.exit(main())
