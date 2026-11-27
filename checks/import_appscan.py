"""导入 HCL AppScan .scan 报告（ZIP：incrementalScanData + templateConfig + RESULTSDB.FDB）。
不依赖 RESULTSDB（Firebird）时，按规则/实体数量输出问题类型级别结果，供客户视角对比。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import collections
import json
import os
import re
import zipfile
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT
OUT = os.path.join(ROOT, 'reports', 'final', 'gate', 'appscan_findings.json')
HIGH_KW = ('xss', 'sql', 'command', 'injection', 'rce', 'xxe', 'deserial', 'ssrf', 'csrf')
LOW_KW = ('header', 'referrer', 'cookie', 'dir', 'information', 'timestamp', 'clickjack', 'frame', 'cache', 'options', 'trace', 'autocomplete')

def severity_for(rule, name, declared=''):
    d = str(declared or '').lower()
    if d in ('high', 'medium', 'low', 'informational', 'critical'):
        return d
    s = (str(rule) + ' ' + str(name)).lower()
    if any((k in s for k in HIGH_KW)):
        return 'high'
    if any((k in s for k in LOW_KW)):
        return 'low'
    return 'medium'

def parse_issue_types(z):
    out = {}
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(z.read('templateConfig.xml'))
        for it in root.iter('IssueType'):
            name = it.get('Name')
            if name:
                out[name] = {'severity': it.get('Severity', '')}
    except Exception:
        pass
    return out

def parse(z):
    issue = parse_issue_types(z)
    findings = []
    entities = 0
    rules = collections.Counter()
    try:
        data = json.loads(z.read('incrementalScanData.json').decode('utf-8', 'replace'))
        for ent in (data.get('TestedEntities') or {}).values():
            entities += 1
            for rid in ent.get('VulnerableRuleIds') or []:
                rules[rid] += 1
    except Exception:
        return {'error': 'incrementalScanData 解析失败', 'findings': []}
    for (rule, cnt) in rules.most_common(100):
        base = re.sub('_\\d+$', '', rule)
        info = issue.get(base) or {}
        name = base
        findings.append({'id': 'EXT-APPSCAN-' + rule, 'rule': rule, 'title': name, 'severity': severity_for(rule, name, info.get('severity', '') if isinstance(info, dict) else ''), 'entities': cnt, 'evidence': f'AppScan 规则 {rule} 命中 {cnt} 个实体', 'confidence': 'external'})
    return {'entities': entities, 'rules': len(rules), 'findings': findings}

def main():
    path = os.environ.get('GATE_APPSCAN_REPORT') or os.environ.get('GATE_EXTERNAL_REPORT', '')
    if not path or not os.path.exists(path) or (not path.lower().endswith('.scan')):
        gc.emit('import_appscan', 'application', 'PASS', [], summary='no AppScan .scan report（未提供 GATE_APPSCAN_REPORT）')
        return
    try:
        z = zipfile.ZipFile(path)
        res = parse(z)
    except Exception as e:
        gc.emit('import_appscan', 'application', 'BLOCKED', [], blocked_reason='AppScan 解析失败: ' + str(e)[:150])
        return
    findings = []
    for f in res.get('findings') or []:
        findings.append(gc.finding(f['id'], 'info' if False else f['severity'], 'AppScan：' + str(f['title'])[:90], evidence=f['evidence'], confidence='external'))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump({'generated_at': __import__('time').strftime('%Y-%m-%dT%H:%M:%S'), 'source': os.path.basename(path), 'entities': res.get('entities'), 'rules': res.get('rules'), 'findings': res.get('findings') or []}, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    gc.emit('import_appscan', 'application', 'PASS', findings, summary=json.dumps({'entities': res.get('entities'), 'rules': res.get('rules'), 'findings': len(findings)}, ensure_ascii=False))
if __name__ == '__main__':
    main()
