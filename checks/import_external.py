"""导入客户/外部扫描器报告（SARIF/Nessus XML/通用 JSON），用于门禁前“客户视角”对比。
未提供报告时 PASS（info），不阻断。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import xml.etree.ElementTree as ET
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc

def parse_sarif(path):
    data = json.load(open(path, encoding='utf-8'))
    out = []
    for run in data.get('runs') or []:
        for r in run.get('results') or []:
            level = (r.get('level') or 'warning').lower()
            sev = {'error': 'high', 'warning': 'medium', 'note': 'info'}.get(level, 'medium')
            loc = ''
            try:
                loc = r['locations'][0]['physicalLocation']['artifactLocation']['uri']
            except Exception:
                pass
            out.append({'id': 'EXT-' + str(r.get('ruleId') or 'sarif'), 'severity': sev, 'title': (r.get('message') or {}).get('text') or str(r.get('ruleId')), 'evidence': loc, 'confidence': 'external'})
    return out

def parse_nessus(path):
    root = ET.parse(path).getroot()
    out = []
    for item in root.iter('ReportItem'):
        sevnum = int(item.get('severity', '0') or 0)
        sev = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}.get(sevnum, 'info')
        out.append({'id': 'EXT-NESSUS-' + (item.get('pluginID') or ''), 'severity': sev, 'title': item.get('pluginName') or 'nessus finding', 'evidence': item.get('port', ''), 'confidence': 'external'})
    return out

def parse_generic(path):
    data = json.load(open(path, encoding='utf-8'))
    items = data.get('findings') or data.get('vulnerabilities') or data
    out = []
    if isinstance(items, list):
        for it in items:
            if not isinstance(it, dict):
                continue
            out.append({'id': 'EXT-' + str(it.get('id') or it.get('title') or 'generic'), 'severity': (it.get('severity') or 'medium').lower(), 'title': it.get('title') or it.get('name') or 'external finding', 'evidence': str(it.get('url') or it.get('endpoint') or '')[:200], 'confidence': 'external'})
    return out

def main():
    path = os.environ.get('GATE_EXTERNAL_REPORT', '')
    if not path or not os.path.exists(path):
        gc.emit('import_external', 'application', 'PASS', [], summary='no external report（未提供 GATE_EXTERNAL_REPORT）')
        return
    low = path.lower()
    try:
        if low.endswith('.sarif') or low.endswith('.json'):
            findings = parse_sarif(path) if 'sarif' in low or 'runs' in open(path, encoding='utf-8').read(500) else parse_generic(path)
        elif low.endswith('.nessus') or low.endswith('.xml'):
            findings = parse_nessus(path)
        else:
            findings = parse_generic(path)
    except Exception as e:
        gc.emit('import_external', 'application', 'BLOCKED', [], blocked_reason='外部报告解析失败: ' + str(e)[:150])
        return
    mapped = [gc.finding(f['id'], 'info', '外部扫描器报告项：' + str(f['title'])[:80], evidence=f.get('evidence', ''), confidence='external') for f in findings[:50]]
    gc.emit('import_external', 'application', 'PASS', mapped, summary=json.dumps({'external_findings': len(findings), 'file': os.path.basename(path)}, ensure_ascii=False))
if __name__ == '__main__':
    main()
