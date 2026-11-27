"""构建全量 API/参数清单：API 文档 HTML + cesauto-api-test Excel + 现有知识库。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import openpyxl
ROOT = 'configured-path'
API_HTML = 'configured-path'
TEST_XLSX = ['configured-path', 'configured-path']
OUT = os.path.join(ROOT, 'knowledge', 'api_inventory.json')
EXISTING = [os.path.join(ROOT, 'knowledge', 'all_backend_endpoints.json'), os.path.join(ROOT, 'knowledge', 'backend_endpoints.json')]

def keys_of(obj, prefix=''):
    out = []
    if isinstance(obj, dict):
        for (k, v) in obj.items():
            out.append(k)
            out += keys_of(v, prefix + k + '.')
    elif isinstance(obj, list) and obj:
        out += keys_of(obj[0], prefix)
    return out

def add(store, method, path, params=None, source=''):
    if not path or not path.startswith('/'):
        return
    key = (method.upper(), path)
    it = store.setdefault(key, {'method': method.upper(), 'path': path, 'query_keys': [], 'body_keys': [], 'sources': []})
    for k in params or []:
        if k not in it['body_keys']:
            it['body_keys'].append(k)
    if source not in it['sources']:
        it['sources'].append(source)

def parse_html(store):
    t = open(API_HTML, encoding='utf-8', errors='replace').read()
    for m in re.finditer('Path：\\s*</strong>\\s*([^<\\s]+)', t):
        path = m.group(1).strip()
        tail = t[m.end():m.end() + 800]
        mm = re.search('Method：\\s*</strong>\\s*(\\w+)', tail)
        method = mm.group(1).upper() if mm else 'POST'
        add(store, method, path, [], 'api_html')

def parse_excel(store):
    for p in TEST_XLSX:
        if not os.path.exists(p):
            continue
        wb = openpyxl.load_workbook(p, data_only=True, read_only=True)
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                vals = [str(v) for v in row if v is not None]
                if len(vals) < 5:
                    continue
                method = None
                path = None
                body = None
                for (i, v) in enumerate(vals):
                    if v.strip().upper() in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'POST_MULTIPART'):
                        method = 'POST' if v.strip().upper() == 'POST_MULTIPART' else v.strip().upper()
                        if i + 1 < len(vals):
                            path = vals[i + 1]
                        body = vals[i + 2] if i + 2 < len(vals) else None
                        break
                if not method or not path:
                    continue
                params = []
                if body:
                    try:
                        params = keys_of(json.loads(body))
                    except Exception:
                        params = re.findall('"([^"]+)"\\s*:', body)
                add(store, method, path, params, os.path.basename(p))
        wb.close()

def parse_existing(store):
    for p in EXISTING:
        if not os.path.exists(p):
            continue
        try:
            data = json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
        for e in data.get('endpoints') or []:
            if isinstance(e, str):
                add(store, 'POST', e, [], os.path.basename(p))
            elif isinstance(e, dict):
                add(store, e.get('method', 'POST'), e.get('path', ''), (e.get('query_keys') or []) + (e.get('body_keys') or []), os.path.basename(p))

def main():
    store = {}
    parse_html(store)
    parse_excel(store)
    parse_existing(store)
    items = sorted(store.values(), key=lambda x: (x['path'], x['method']))
    out = {'generated_at': __import__('time').strftime('%Y-%m-%dT%H:%M:%S'), 'count': len(items), 'endpoints': items}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(out, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('inventory', len(items), '->', OUT)
    from collections import Counter
    print(Counter((x['method'] for x in items)))
if __name__ == '__main__':
    main()
