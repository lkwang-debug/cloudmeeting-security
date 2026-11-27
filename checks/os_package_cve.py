"""组件/主机：系统包 CVE 扫描（OpenSSH/OpenSSL/glibc/kernel/sudo 等，OSV）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import paramiko
import requests
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
try:
    from checks import os_mapping
except ImportError:
    import os_mapping
HOSTS = os.environ.get('GATE_OS_HOSTS', '' + _pub.shell('SEC_DB_HOST') + ',' + _pub.shell('SEC_DB_HOST') + '').split(',')
PWD_MAP = {_pub.env('SEC_SSH_HOST', ''): os.environ.get('GATE_SSH_PASS_155', _pub.env('SEC_SSH_PASSWORD', '')), _pub.env('SEC_SSH_HOST', ''): os.environ.get('GATE_SSH_PASS_180', 'FsMeeting.com')}
TARGETS = ('openssh', 'openssl', 'glibc', 'kernel')
OSV_BATCH = 'https://api.osv.dev/v1/querybatch'

def os_of(host, c):
    (i, o, e) = c.exec_command('cat /etc/os-release 2>/dev/null', timeout=15)
    t = o.read().decode('utf-8', 'replace')
    m = re.search('^ID="?([^"\\n]+)', t, re.M)
    v = re.search('^VERSION_ID="?([^"\\n]+)', t, re.M)
    return (m.group(1) if m else '', v.group(1) if v else '')

def packages(c):
    (i, o, e) = c.exec_command("rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}\\n' 2>/dev/null | sort -u", timeout=60)
    out = []
    for line in o.read().decode('utf-8', 'replace').splitlines():
        if '|' in line:
            (n, v) = line.split('|', 1)
            if any((t in n.lower() for t in TARGETS)):
                out.append({'name': n.strip(), 'version': v.strip()})
    return out

def main():
    (findings, probes, details, seen) = ([], [], [], set())
    for host in [h.strip() for h in HOSTS if h.strip()]:
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(host, 22, _pub.env('SEC_SSH_USER'), PWD_MAP.get(host, ''), timeout=8)
            (distro, ver) = os_of(host, c)
            (eco, conf, note) = os_mapping.ecosystem_for(distro, ver)
            pkgs = packages(c)
            c.close()
        except Exception as e:
            probes.append({'host': host, 'error': str(e)[:120]})
            continue
        probes.append({'host': host, 'distro': distro, 'version': ver, 'ecosystem': eco, 'confidence': conf, 'packages': len(pkgs)})
        if not eco or not pkgs:
            continue
        queries = [{'package': {'name': p['name'], 'ecosystem': eco}, 'version': p['version'].split('-')[0]} for p in pkgs[:80]]
        try:
            r = requests.post(OSV_BATCH, json={'queries': queries}, timeout=30)
            results = r.json().get('results', [])
        except Exception as e:
            probes[-1]['osv_error'] = str(e)[:100]
            continue
        for (p, res) in zip(pkgs, results):
            for v in res.get('vulns') or []:
                vid = v.get('id')
                if not vid:
                    continue
                key = (host, p['name'], vid)
                if key in seen:
                    continue
                seen.add(key)
                details.append({'host': host, 'package': p['name'], 'version': p['version'], 'vuln': vid, 'ecosystem': eco, 'confidence': conf, 'note': note})
    json.dump({'generated_at': __import__('time').strftime('%Y-%m-%dT%H:%M:%S'), 'count': len(details), 'details': details}, open(os.path.join(gc.ROOT, 'reports', 'final', 'gate', 'os_package_cve_details.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    if details:
        findings.append(gc.finding('OS-PKG-CVE-CANDIDATES', 'info', f'系统包 CVE 候选 {len(details)} 条（需按发行版补丁确认）', evidence=json.dumps({'top': details[:10]}, ensure_ascii=False)[:500], remediation='参考 os_package_cve_details.json，按厂商补丁确认/升级'))
    gc.emit('os_package_cve', 'component', 'PASS', findings, summary=json.dumps({'hosts': probes, 'candidates': len(details), 'detail_file': 'os_package_cve_details.json'}, ensure_ascii=False)[:800])
if __name__ == '__main__':
    main()
