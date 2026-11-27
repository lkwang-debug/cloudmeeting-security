"""V8.2 门禁 truth set：按已知正/负样本计算检出率与客户报告映射覆盖。

用法：python runner/build_gate_truth_set.py
输出：reports/final/gate/gate_truth_set.json / GATE_TRUTH_SET.md
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, 'reports', 'final', 'gate', 'gate_result.json')
MATRIX = os.path.join(ROOT, 'knowledge', 'gate_matrix.yaml')
OUT_DIR = os.path.join(ROOT, 'reports', 'final', 'gate')
POSITIVES = [{'id': 'DB-MD5', 'check': 'crypto_inventory', 'match': 'CRYPTO-DB-MD5'}, {'id': 'JS-3DES', 'check': 'client_crypto', 'match': 'CLIENT-HARDCODED-CRYPTO'}, {'id': 'JS-DEFAULT-PASS', 'check': 'secret_scan', 'match': 'CRYPTO-PLAINTEXT-SECRET'}, {'id': 'TRIVY-CVE', 'check': 'trivy_cve', 'match': 'TRIVY-*'}, {'id': 'GRYPE-CVE', 'check': 'grype_cve', 'match': 'GRYPE-*'}, {'id': 'RCE-DEP-SNAKEYAML', 'check': 'dependency_rce', 'match': 'RCE-DEP-org.yaml:snakeyaml'}]
NEGATIVES = ['xss_full', 'upload_webshell', 'rce_probe', 'file_download', 'idor_matrix', 'login_policy', 'auth_token_checks', 'soap_checks', 'plaintext_http', 'rce_deserialization', 'upload_content', 'xss_dom', 'xss_crawl', 'idor_h5', 'login_rate_limit', 'crypto_app']

def load(path, default):
    if not os.path.exists(path):
        return default
    try:
        return json.load(open(path, encoding='utf-8'))
    except Exception:
        return default

def evaluate(gate, matrix):
    checks = gate.get('checks') or {}
    pos = []
    for p in POSITIVES:
        cid = p['check']
        c = checks.get(cid) or {}
        evid = []
        ev = os.path.join(ROOT, 'reports', 'final', 'gate', 'evidence', cid + '.json')
        if os.path.exists(ev):
            try:
                evid = json.load(open(ev, encoding='utf-8')).get('findings') or []
            except Exception:
                evid = []
        matched = False
        for f in evid:
            fid = str(f.get('id', ''))
            if p['match'].endswith('*'):
                matched = fid.startswith(p['match'][:-1]) and f.get('severity') in ('critical', 'high')
            else:
                matched = fid == p['match']
            if matched:
                break
        pos.append({'sample': p['id'], 'check': cid, 'matched': matched, 'check_status': c.get('status')})
    neg = []
    for cid in NEGATIVES:
        c = checks.get(cid)
        if not c:
            continue
        ev = os.path.join(ROOT, 'reports', 'final', 'gate', 'evidence', cid + '.json')
        findings = []
        if os.path.exists(ev):
            try:
                findings = json.load(open(ev, encoding='utf-8')).get('findings') or []
            except Exception:
                findings = []
        bad = [f for f in findings if f.get('severity') in ('critical', 'high')]
        neg.append({'check': cid, 'false_positive': len(bad), 'findings': len(findings)})
    items = []
    for r in (matrix.get('reports') or {}).values():
        items += r.get('items') or []
    mapped = 0
    executed = 0
    for it in items:
        cid = it.get('check')
        if cid and cid != 'manual':
            mapped += 1
            if cid in checks:
                executed += 1
    tp = len([p for p in pos if p['matched']])
    fp = sum((n['false_positive'] for n in neg))
    return {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'positives': pos, 'negatives': neg, 'metrics': {'positive_samples': len(pos), 'positive_detected': tp, 'detection_rate': round(tp / len(pos), 3) if pos else None, 'negative_checks': len(neg), 'false_positives': fp, 'report_items': len(items), 'mapped': mapped, 'executed': executed, 'mapped_pct': round(mapped / len(items) * 100, 1) if items else 0, 'executed_pct': round(executed / len(items) * 100, 1) if items else 0}}

def main():
    gate = load(GATE, {})
    matrix = yaml.safe_load(open(MATRIX, encoding='utf-8')) if os.path.exists(MATRIX) else {}
    out = evaluate(gate, matrix)
    os.makedirs(OUT_DIR, exist_ok=True)
    json.dump(out, open(os.path.join(OUT_DIR, 'gate_truth_set.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    m = out['metrics']
    lines = ['# V8.2 门禁 Truth Set / 覆盖指标', '', f"- 时间：{out['generated_at']}", '', f"- 正样本检出：{m['positive_detected']}/{m['positive_samples']}（detection_rate={m['detection_rate']}）", f"- 负样本误报：{m['false_positives']}", f"- 客户报告映射：{m['mapped']}/{m['report_items']}（{m['mapped_pct']}%），已执行检查：{m['executed']}（{m['executed_pct']}%）", '', '## 正样本', '', '| 样本 | 检查 | 是否检出 | 检查状态 |', '|---|---|---|---|']
    for p in out['positives']:
        lines.append(f"| {p['sample']} | {p['check']} | {('✅' if p['matched'] else '❌')} | {p['check_status']} |")
    lines += ['', '## 负样本（预期无高危）', '', '| 检查 | 高危误报 | 发现数 |', '|---|---|---|']
    for n in out['negatives']:
        lines.append(f"| {n['check']} | {n['false_positive']} | {n['findings']} |")
    open(os.path.join(OUT_DIR, 'GATE_TRUTH_SET.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    print(json.dumps(m, ensure_ascii=False))
if __name__ == '__main__':
    main()
