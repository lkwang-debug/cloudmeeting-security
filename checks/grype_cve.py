"""组件安全：Grype SBOM CVE 结果导入（grype_sbom.json）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT
PATH = os.environ.get('GATE_GRYPE_JSON') or os.path.join(ROOT, 'reports', 'final', 'gate', 'grype_product.json')
if not os.path.exists(PATH):
    PATH = os.path.join(ROOT, 'reports', 'final', 'gate', 'grype_sbom.json')

def parse(data, limit=120):
    out = []
    seen = set()
    for m in data.get('matches') or []:
        v = m.get('vulnerability') or {}
        a = m.get('artifact') or {}
        sev = str(v.get('severity') or '').lower()
        key = (v.get('id'), a.get('name'), a.get('version'))
        if key in seen:
            continue
        seen.add(key)
        out.append({'id': 'GRYPE-' + str(v.get('id')), 'severity': sev or 'unknown', 'title': f"Grype: {a.get('name')} {a.get('version')} 命中 {v.get('id')}", 'evidence': f"fix={v.get('fix', {}).get('versions')} purl={a.get('purl', '')}", 'confidence': 'high'})
        if len(out) >= limit:
            break
    return out

def main():
    if not os.path.exists(PATH):
        gc.emit('grype_cve', 'component', 'BLOCKED', [], blocked_reason='grype_sbom.json 不存在；需在 worker 运行 grype 扫描 CycloneDX')
        return
    try:
        data = json.load(open(PATH, encoding='utf-8'))
    except Exception as e:
        gc.emit('grype_cve', 'component', 'BLOCKED', [], blocked_reason='Grype 结果解析失败: ' + str(e)[:120])
        return
    allv = parse(data)
    findings = []
    for f in allv:
        if f['severity'] in ('critical', 'high'):
            findings.append(gc.finding(f['id'], f['severity'], f['title'], evidence=f['evidence'], remediation='升级组件/使用修复版本'))
    gc.emit('grype_cve', 'component', 'PASS', findings, summary=json.dumps({'grype_matches': len(data.get('matches') or []), 'high_critical': len(findings), 'by_sev': {s: sum((1 for f in allv if f['severity'] == s)) for s in ('critical', 'high', 'medium', 'low')}}, ensure_ascii=False))
if __name__ == '__main__':
    main()
