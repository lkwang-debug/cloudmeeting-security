"""Week0: 静态解析 915 条功能用例 -> knowledge/endpoints.json（只读 Excel，不修改源项目）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import datetime
import pandas as pd
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XLSX = os.path.join(ROOT, 'sources', 'ces-api', 'data', 'test_data_v2.xlsx')
OUT = os.path.join(ROOT, 'knowledge', 'endpoints.json')
COLS = ['用例ID', '用例标题', '请求方法', '接口路径', '请求头', '请求数据', '提取规则', '响应断言', '数据库断言', '是否运行']
AUTH_RULES = [('^/api/v1/', 'backend_token'), ('^/meeting-resource-server/', 'oauth2_bearer'), ('^/fmapi/', 'fmapi_sign'), ('^/open/', 'anonymous_or_basic'), ('^/serv/v1/', 'backend_token'), ('^/auth/v1/', 'anonymous')]

def infer_auth(path):
    for (pat, name) in AUTH_RULES:
        if re.search(pat, path):
            return name
    return 'unknown'

def norm_path(p):
    if pd.isna(p):
        return None
    s = str(p).strip()
    if not s:
        return None
    m = re.match('https?://[^/]+(/.+)$', s)
    if m:
        s = m.group(1)
    s = s.split('?')[0]
    if not s.startswith('/'):
        s = '/' + s
    return s

def norm_method(m):
    if pd.isna(m):
        return 'POST'
    return str(m).strip().upper() or 'POST'

def is_enabled(v):
    return str(v).strip().lower() in ('是', 'y', 'yes', 'true', '1')

def main():
    xls = pd.ExcelFile(XLSX)
    endpoints = {}
    per_sheet = {}
    total = enabled_total = 0
    step_total = step_enabled = 0
    for sh in xls.sheet_names:
        df = pd.read_excel(XLSX, sheet_name=sh)
        for c in COLS:
            if c not in df.columns:
                df[c] = None
        sh_total = sh_enabled = sh_steps = 0
        for (_, row) in df.iterrows():
            cid = str(row['用例ID']).strip() if not pd.isna(row['用例ID']) else ''
            if not cid:
                continue
            path = norm_path(row['接口路径'])
            enabled = is_enabled(row['是否运行'])
            if not path:
                sh_steps += 1
                step_total += 1
                if enabled:
                    step_enabled += 1
                continue
            method = norm_method(row['请求方法'])
            total += 1
            sh_total += 1
            if enabled:
                enabled_total += 1
                sh_enabled += 1
            key = f'{method} {path}'
            e = endpoints.setdefault(key, {'key': key, 'method': method, 'path_template': path, 'auth_inferred': infer_auth(path), 'status': 'discovered', 'sheets': [], 'source_case_ids': [], 'titles': [], 'enabled_cases': 0, 'total_cases': 0, 'sample_headers': None, 'sample_body': None})
            if sh not in e['sheets']:
                e['sheets'].append(sh)
            e['source_case_ids'].append(cid)
            if row['用例标题'] is not None and (not pd.isna(row['用例标题'])):
                e['titles'].append(str(row['用例标题']))
            e['total_cases'] += 1
            if enabled:
                e['enabled_cases'] += 1
            if enabled and e['sample_body'] is None and (not pd.isna(row['请求数据'])):
                e['sample_body'] = str(row['请求数据'])[:2000]
            if enabled and e['sample_headers'] is None and (not pd.isna(row['请求头'])):
                e['sample_headers'] = str(row['请求头'])[:500]
        per_sheet[sh] = {'endpoint_cases': sh_total, 'enabled': sh_enabled, 'business_steps': sh_steps}
    result = {'meta': {'source': XLSX.replace(ROOT + os.sep, ''), 'generated_at': datetime.datetime.now().isoformat(timespec='seconds'), 'case_total': total, 'case_enabled': enabled_total, 'business_steps': step_total, 'business_steps_enabled': step_enabled, 'endpoint_unique': len(endpoints), 'sheets': per_sheet}, 'endpoints': sorted(endpoints.values(), key=lambda x: x['key'])}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    print(json.dumps(result['meta'], ensure_ascii=False, indent=1))
    print('written:', OUT)
    print('\n候选安全场景端点:')
    for e in result['endpoints']:
        low = e['path_template'].lower()
        if any((k in low for k in ('getroominfo', 'room/add', 'room/update', 'user/list', 'user/add', 'user/update', 'record', 'download', 'export'))):
            print('  ', e['key'], '| auth=', e['auth_inferred'], '| cases=', e['total_cases'], '| enabled=', e['enabled_cases'])
if __name__ == '__main__':
    main()
