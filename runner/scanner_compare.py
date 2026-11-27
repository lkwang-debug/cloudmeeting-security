"""客户/外部扫描器报告与门禁结果对比（客户视角差异）。
用法：先设置 GATE_EXTERNAL_REPORT 并运行 import_external，再运行本脚本。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, 'reports', 'final', 'gate', 'gate_result.json')
EXT = os.path.join(ROOT, 'reports', 'final', 'gate', 'evidence', 'import_external.json')
OUT = os.path.join(ROOT, 'reports', 'final', 'gate')
RULES = [('xss', 'xss_full'), ('跨站', 'xss_full'), ('upload', 'upload_webshell'), ('上传', 'upload_webshell'), ('rce', 'rce_probe'), ('命令执行', 'rce_probe'), ('反序列化', 'rce_probe'), ('command', 'rce_probe'), ('execution', 'rce_probe'), ('sql', 'injection_matrix'), ('注入', 'injection_matrix'), ('header', 'security_headers'), ('hsts', 'security_headers'), ('cors', 'security_headers'), ('content-security', 'security_headers'), ('contentsecurity', 'security_headers'), ('referrer', 'security_headers'), ('frame', 'security_headers'), ('cachedssl', 'crypto_inventory'), ('getparamoverssl', 'plaintext_http'), ('brokenfunction', 'idor_matrix'), ('email', 'secret_scan'), ('internalip', 'secret_scan'), ('pathdisclosure', 'secret_scan'), ('dirfound', 'file_download'), ('springendpoints', 'endpoint_exposure'), ('actuator', 'endpoint_exposure'), ('swagger', 'endpoint_exposure'), ('cookie', 'secret_scan'), ('download', 'file_download'), ('下载', 'file_download'), ('idor', 'idor_matrix'), ('越权', 'idor_matrix'), ('login', 'login_policy'), ('弱口令', 'login_policy'), ('暴力', 'login_policy'), ('sms', 'sms_bomb'), ('短信', 'sms_bomb'), ('tls', 'crypto_inventory'), ('ssl', 'crypto_inventory'), ('加密', 'crypto_inventory'), ('cve', 'cve_gate'), ('组件', 'cve_gate'), ('依赖', 'cve_gate')]

def map_check(title):
    t = str(title).lower()
    for (kw, cid) in RULES:
        if kw in t:
            return cid
    return None

def compare(gate, external_findings):
    gate_checks = set((gate.get('checks') or {}).keys())
    rows = []
    for f in external_findings:
        cid = map_check(f.get('title', ''))
        rows.append({'external': f.get('title'), 'severity': f.get('severity'), 'mapped_check': cid, 'covered': bool(cid and cid in gate_checks)})
    covered = [r for r in rows if r['covered']]
    uncovered = [r for r in rows if not r['covered']]
    unseen = [c for c in ('xss_full', 'upload_webshell', 'rce_probe', 'file_download', 'idor_matrix', 'login_policy') if c not in gate_checks]
    return {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'external_total': len(rows), 'covered': len(covered), 'uncovered': len(uncovered), 'coverage_pct': round(len(covered) / len(rows) * 100, 1) if rows else None, 'rows': rows, 'uncovered_findings': uncovered, 'checks_not_in_gate': unseen}

def main():
    gate = json.load(open(GATE, encoding='utf-8')) if os.path.exists(GATE) else {}
    ext = []
    if os.path.exists(EXT):
        ev = json.load(open(EXT, encoding='utf-8'))
        ext = ev.get('findings') or []
    appscan = os.path.join(OUT, 'appscan_findings.json')
    if os.path.exists(appscan):
        try:
            for f in json.load(open(appscan, encoding='utf-8')).get('findings') or []:
                ext.append({'title': f.get('title'), 'severity': f.get('severity'), 'rule': f.get('rule'), 'evidence': f.get('evidence')})
        except Exception:
            pass
    if not ext:
        lines = ['# 客户扫描器对比', '', '- 未导入外部报告（设置 GATE_EXTERNAL_REPORT 后重跑 import_external）。', '- 当前门禁检查可作为客户视角的基础，但无法量化差异。']
        open(os.path.join(OUT, 'GATE_EXTERNAL_COMPARE.md'), 'w', encoding='utf-8').write('\n'.join(lines))
        print('no external report')
        return
    res = compare(gate, ext)
    json.dump(res, open(os.path.join(OUT, 'GATE_EXTERNAL_COMPARE.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    lines = ['# 客户扫描器与门禁对比', '', f"- 时间：{res['generated_at']}", f"- 外部发现：{res['external_total']}，门禁有对应检查：{res['covered']}，缺检查：{res['uncovered']}", f"- 覆盖比例：{res['coverage_pct']}%", '', '| 外部发现 | 严重性 | 映射检查 | 是否覆盖 |', '|---|---|---|---|']
    for r in res['rows'][:50]:
        lines.append(f"| {str(r['external'])[:60]} | {r['severity']} | {r['mapped_check']} | {r['covered']} |")
    if res['checks_not_in_gate']:
        lines += ['', '## 门禁缺少的检查', *[f'- {c}' for c in res['checks_not_in_gate']]]
    open(os.path.join(OUT, 'GATE_EXTERNAL_COMPARE.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    print(json.dumps({k: res[k] for k in ('external_total', 'covered', 'uncovered', 'coverage_pct')}, ensure_ascii=False))
if __name__ == '__main__':
    main()
