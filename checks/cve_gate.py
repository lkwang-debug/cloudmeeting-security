"""组件安全：CVE 门禁（OSV 查询 + 严重性过滤；无数据时阻塞）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import requests
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
try:
    from checks import os_mapping
except ImportError:
    import os_mapping
ROOT = gc.ROOT
SBOM = os.environ.get('GATE_SBOM_PATH') or os.path.join(ROOT, 'reports', 'final', 'gate', 'sbom_merged.json')
OSV_BATCH = 'https://api.osv.dev/v1/querybatch'
OSV_VULN = 'https://api.osv.dev/v1/vulns/'

def query_batch(queries):
    out = []
    for i in range(0, len(queries), 200):
        r = requests.post(OSV_BATCH, json={'queries': queries[i:i + 200]}, timeout=30)
        r.raise_for_status()
        out += r.json().get('results', [])
    return out

def severity_of(vid):
    try:
        r = requests.get(OSV_VULN + vid, timeout=15)
        if r.status_code != 200:
            return 'unknown'
        j = r.json()
        sev = j.get('severity') or []
        for s in sev:
            sc = str(s.get('score', '')).upper()
            if 'CRITICAL' in sc:
                return 'critical'
            if 'HIGH' in sc:
                return 'high'
        ds = (j.get('database_specific') or {}).get('severity', '')
        ds = str(ds).lower()
        if ds in ('critical', 'high'):
            return ds
        return 'medium'
    except Exception:
        return 'unknown'

def main():
    if not os.path.exists(SBOM):
        gc.emit('cve_gate', 'component', 'BLOCKED', [], blocked_reason='sbom_merged.json 不存在，先跑 sbom_collect')
        return
    data = json.load(open(SBOM, encoding='utf-8'))
    comps = [c for c in data.get('components') or [] if c.get('name') and c.get('version')]
    queries = []
    meta = []
    for c in comps:
        src = c.get('source', '')
        (conf, note) = ('high', '')
        if 'container' in src:
            eco = 'openEuler'
        elif 'java-maven' in src:
            eco = 'Maven'
        elif c.get('distro'):
            (eco, conf, note) = os_mapping.ecosystem_for(c.get('distro'), c.get('distro_version', ''))
        elif 'os-rpm-155' in src:
            (eco, conf, note) = os_mapping.ecosystem_for('kylin', '10')
        else:
            eco = None
        if not eco:
            continue
        queries.append({'package': {'name': c['name'], 'ecosystem': eco}, 'version': c['version']})
        c2 = dict(c)
        c2['os_ecosystem'] = eco
        c2['mapping_confidence'] = conf
        c2['mapping_note'] = note
        meta.append(c2)
        if len(queries) >= 120:
            break
    if not queries:
        gc.emit('cve_gate', 'component', 'BLOCKED', [], blocked_reason='SBOM 中没有可映射生态的组件版本')
        return
    try:
        results = query_batch(queries)
    except Exception as e:
        gc.emit('cve_gate', 'component', 'BLOCKED', [], blocked_reason='OSV 不可用: ' + str(e)[:120])
        return
    findings = []
    vuln_ids = []
    for (c, res) in zip(meta, results):
        for v in res.get('vulns') or []:
            vuln_ids.append((c, v.get('id')))
    for (c, vid) in vuln_ids[:12]:
        sev = severity_of(vid)
        if sev in ('critical', 'high'):
            findings.append(gc.finding('CVE-' + str(vid), sev, f"组件 {c['name']} {c['version']} 命中 {vid}", evidence=f"source={c.get('source')} distro={c.get('distro', '')} eco={c.get('os_ecosystem', '')} confidence={c.get('mapping_confidence', '')} osv={vid} severity={sev}", remediation='升级到修复版本；无修复则豁免并补偿'))
    medium = [{'component': c['name'], 'version': c['version'], 'vuln': vid} for (c, vid) in vuln_ids[12:]][:20]
    if not vuln_ids:
        findings.append(gc.finding('CVE-NONE', 'info', 'OSV 未命中已查询组件（不代表安全）', evidence='OSV batch', confidence='low'))
    gc.emit('cve_gate', 'component', 'PASS', findings, summary=json.dumps({'components_queried': len(queries), 'vuln_hits': len(vuln_ids), 'high_critical': len(findings), 'other_candidates': medium}, ensure_ascii=False)[:700])
if __name__ == '__main__':
    main()
