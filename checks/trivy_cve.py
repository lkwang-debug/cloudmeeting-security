"""组件安全：Trivy SBOM CVE 结果导入（trivy_sbom.json）。"""
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
PATH = os.environ.get('GATE_TRIVY_JSON') or os.path.join(ROOT, 'reports', 'final', 'gate', 'trivy_product.json')
if not os.path.exists(PATH):
    PATH = os.path.join(ROOT, 'reports', 'final', 'gate', 'trivy_sbom.json')

def parse(data, limit=200):
    out = []
    seen = set()
    for r in data.get('Results') or []:
        for v in r.get('Vulnerabilities') or []:
            vid = v.get('VulnerabilityID')
            pkg = v.get('PkgName')
            ver = v.get('InstalledVersion')
            key = (vid, pkg, ver)
            if key in seen:
                continue
            seen.add(key)
            sev = str(v.get('Severity') or 'unknown').lower()
            out.append({'id': 'TRIVY-' + str(vid), 'severity': sev, 'title': f'Trivy: {pkg} {ver} 命中 {vid}', 'evidence': f"fixed={v.get('FixedVersion')} target={r.get('Target')}", 'confidence': 'high'})
            if len(out) >= limit:
                return out
    return out

def main():
    if not os.path.exists(PATH):
        gc.emit('trivy_cve', 'component', 'BLOCKED', [], blocked_reason='trivy_sbom.json 不存在；需运行 trivy sbom 扫描')
        return
    try:
        data = json.load(open(PATH, encoding='utf-8'))
    except Exception as e:
        gc.emit('trivy_cve', 'component', 'BLOCKED', [], blocked_reason='Trivy 结果解析失败: ' + str(e)[:120])
        return
    allv = parse(data)
    findings = [gc.finding(f['id'], f['severity'], f['title'], evidence=f['evidence'], remediation='升级组件/使用修复版本') for f in allv if f['severity'] in ('critical', 'high')]
    gc.emit('trivy_cve', 'component', 'PASS', findings, summary=json.dumps({'trivy_vulns': len(allv), 'high_critical': len(findings), 'by_sev': {s: sum((1 for f in allv if f['severity'] == s)) for s in ('critical', 'high', 'medium', 'low')}}, ensure_ascii=False))
if __name__ == '__main__':
    main()
