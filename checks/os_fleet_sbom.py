"""多发行版主机 OS 包采集（Kylin/openEuler/CentOS/UOS 等），用于组件 CVE 门禁。
目标：GATE_OS_TARGETS JSON 列表 [{host,user,pass,label}]，默认 155。
输出 reports/final/gate/os_fleet_sbom.json。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT
OUT = os.path.join(ROOT, 'reports', 'final', 'gate', 'os_fleet_sbom.json')

def default_targets():
    raw = os.environ.get('GATE_OS_TARGETS', '')
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return [{'host': _pub.env('SEC_SSH_HOST', ''), 'user': 'root', 'pass': _pub.env('SEC_SSH_PASSWORD', ''), 'label': 'host-155'}]

def collect(host):
    import paramiko
    out = {'label': host.get('label'), 'host': host['host'], 'os': {}, 'components': [], 'error': ''}
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host['host'], 22, host.get('user', 'root'), host.get('pass', ''), timeout=8)
        (i, o, e) = c.exec_command('cat /etc/os-release 2>/dev/null', timeout=15)
        txt = o.read().decode('utf-8', 'replace')
        info = {}
        for line in txt.splitlines():
            if '=' in line:
                (k, v) = line.split('=', 1)
                info[k.strip()] = v.strip().strip('"')
        out['os'] = {'id': info.get('ID', ''), 'version_id': info.get('VERSION_ID', ''), 'pretty': info.get('PRETTY_NAME', '')}
        (i, o, e) = c.exec_command("command -v rpm >/dev/null && rpm -qa || dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null", timeout=90)
        for line in o.read().decode('utf-8', 'replace').splitlines():
            line = line.strip()
            if not line:
                continue
            if '\t' in line:
                (name, ver) = line.split('\t', 1)
            else:
                m = re.match('^(.+)-([^-]+)-([^-]+)\\.(\\w+)$', line)
                if not m:
                    continue
                (name, ver) = (m.group(1), f'{m.group(2)}-{m.group(3)}')
            out['components'].append({'name': name, 'version': ver, 'distro': out['os']['id'], 'distro_version': out['os']['version_id']})
        c.close()
    except Exception as ex:
        out['error'] = str(ex)[:150]
    return out

def main():
    targets = default_targets()
    results = []
    for t in targets:
        r = collect(t)
        results.append(r)
        if r.get('error'):
            print('target error', r.get('host'), r['error'])
    components = []
    for r in results:
        for c in r.get('components') or []:
            c2 = dict(c)
            c2['source'] = 'os-fleet-' + str(r.get('label'))
            components.append(c2)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump({'generated_at': __import__('time').strftime('%Y-%m-%dT%H:%M:%S'), 'targets': results, 'component_count': len(components), 'components': components}, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    blocked = [r['host'] for r in results if r.get('error')]
    findings = []
    if blocked:
        findings.append(gc.finding('OS-FLEET-PARTIAL', 'medium', f'{len(blocked)} 个主机采集失败', evidence=','.join(blocked)[:200]))
    gc.emit('os_fleet_sbom', 'component', 'BLOCKED' if blocked and (not components) else 'PASS', findings, summary=json.dumps({'targets': [{'host': r['host'], 'os': r['os'], 'components': len(r.get('components') or []), 'error': r.get('error')} for r in results], 'components': len(components)}, ensure_ascii=False)[:800], blocked_reason='部分主机不可达: ' + ','.join(blocked)[:150] if blocked else '')
if __name__ == '__main__':
    main()
