"""安装部署包扫描（无源码时）：包清单、SBOM、配置/secret 线索。
目标目录：GATE_DEPLOY_PKG（默认 /hst/4.40.0.7）。
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
OUT = os.path.join(ROOT, 'reports', 'final', 'gate', 'deploy_package_scan.json')
PKG = os.environ.get('GATE_DEPLOY_PKG', '/hst/4.40.0.7')
SECRET_RE = re.compile('(?i)(password|passwd|secret|private[_-]?key|access[_-]?key)\\s*[:=]\\s*[\'\\"]?([^\\s\'\\"]{4,80})')

def ssh_run(cmd, timeout=180):
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=8)
        (i, o, e) = c.exec_command(cmd, timeout=timeout)
        out = (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
        c.close()
        return out
    except Exception as ex:
        return 'ERR:' + str(ex)[:150]

def main():
    findings = []
    details = {}
    listing = ssh_run('ls -lh %s 2>/dev/null | head -30' % PKG, 60)
    details['packages'] = listing
    sbom = ssh_run("tar -xOzf %s/fsp-deploy-web-*.tar.gz 'fsp-deploy-web-*/sbom.spdx.json' 2>/dev/null | head -c 4000" % PKG, 120)
    packages = []
    if sbom and (not sbom.startswith('ERR:')):
        try:
            j = json.loads(sbom[sbom.find('{'):])
            packages = [{'name': p.get('name'), 'version': p.get('versionInfo')} for p in j.get('packages') or []]
        except Exception:
            pass
    details['package_sbom'] = packages
    files = ssh_run('find %s/hstdeploy -maxdepth 3 -type f -size -2M 2>/dev/null | head -200' % PKG, 120)
    details['config_files'] = files.splitlines()[:200]
    candidates = [p for p in details['config_files'] if re.search('\\.(yml|yaml|env|conf|properties|sh|json)$', p)]
    secrets = []
    if candidates:
        cmd = "grep -RInE '(?i)(password|passwd|secret|private_key|access_key)[[:space:]]*[:=]' " + ' '.join(("'%s'" % p.replace("'", '') for p in candidates[:40])) + ' 2>/dev/null | head -30'
        hits = ssh_run(cmd, 120)
        for line in hits.splitlines():
            m = SECRET_RE.search(line)
            if m:
                val = m.group(2)
                masked = val[:2] + '****' + val[-2:] if len(val) > 6 else '****'
                secrets.append({'file': line.split(':')[0], 'key': m.group(1), 'value_masked': masked})
    details['secret_hits'] = secrets
    if secrets:
        findings.append(gc.finding('PKG-CONFIG-SECRET', 'medium', f'部署包配置中发现 {len(secrets)} 处疑似明文密码/密钥', evidence=json.dumps(secrets[:5], ensure_ascii=False), remediation='改用密钥管理/环境变量；确认是否为默认/测试值'))
    if not packages:
        findings.append(gc.finding('PKG-SBOM-MISSING', 'low', '部署包未发现可解析 SBOM', evidence=sbom[:200]))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump({'generated_at': __import__('time').strftime('%Y-%m-%dT%H:%M:%S'), 'package_dir': PKG, 'details': details}, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    gc.emit('deploy_package_scan', 'component', 'PASS', findings, summary=json.dumps({'packages': len(packages), 'configs': len(candidates), 'secret_hits': len(secrets)}, ensure_ascii=False))
if __name__ == '__main__':
    main()
