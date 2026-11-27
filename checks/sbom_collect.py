"""组件安全：合并 SBOM（OS 包 + 容器包 + Java 依赖）生成完整组件清单。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT
OUT = os.environ.get('GATE_SBOM_OUT') or os.path.join(ROOT, 'reports', 'final', 'gate', 'sbom_merged.json')

def load(path):
    p = os.path.join(ROOT, path)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding='utf-8'))
        except Exception:
            return {}
    return {}

def maven_components():
    """从 host 155 的 jar 中提取 Maven 坐标（pom.properties）。"""
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
        cmd = 'for j in $(find /hst -name \'*.jar\' 2>/dev/null | grep -v \'/jdk\' | head -80); do p=$(unzip -p "$j" \'META-INF/maven/*/pom.properties\' 2>/dev/null | tr -d \'\\r\'); if [ -n "$p" ]; then echo "JAR:$j"; echo "$p" | head -6; fi; done'
        (i, o, e) = c.exec_command(cmd, timeout=240)
        text = o.read().decode('utf-8', 'replace')
        c.close()
    except Exception:
        return []
    comps = []
    cur = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('JAR:'):
            cur = {'jar': line[4:], 'group': '', 'artifact': '', 'version': ''}
        elif cur is not None and '=' in line:
            (k, v) = line.split('=', 1)
            k = k.strip()
            v = v.strip()
            if k == 'groupId':
                cur['group'] = v
            elif k == 'artifactId':
                cur['artifact'] = v
            elif k == 'version':
                cur['version'] = v
            if cur['group'] and cur['artifact'] and cur['version']:
                comps.append({'name': cur['group'] + ':' + cur['artifact'], 'version': cur['version'], 'source': 'java-maven', 'type': 'java-maven', 'path': cur['jar']})
                cur = None
    return comps

def main():
    components = []
    sources = {}
    p1 = load('reports/p1/sbom_cyclonedx.json')
    for c in p1.get('components') or []:
        components.append({'name': c.get('name'), 'version': c.get('version'), 'source': 'os-rpm-155', 'type': 'os', 'distro': 'kylin', 'distro_version': '10'})
    sources['os_rpm_155'] = len(p1.get('components') or [])
    cont = load('reports/final/container_sboms/containers_cyclonedx.json')
    for c in cont.get('components') or []:
        components.append({'name': c.get('name'), 'version': c.get('version'), 'source': 'container', 'type': 'os-container'})
    sources['container'] = len(cont.get('components') or [])
    java = load('reports/final/java_sbom/java_dependencies.json')
    for d in java.get('dependencies') or []:
        components.append({'name': d.get('jar'), 'version': '', 'source': 'java-jar', 'type': 'java', 'path': d.get('path')})
    sources['java'] = len(java.get('dependencies') or [])
    fleet = load('reports/final/gate/os_fleet_sbom.json')
    for c in fleet.get('components') or []:
        components.append(c)
    sources['os_fleet'] = len(fleet.get('components') or [])
    maven = maven_components()
    for c in maven:
        components.append(c)
    sources['java_maven'] = len(maven)
    seen = set()
    uniq = []
    for c in components:
        key = (c.get('name'), c.get('version'), c.get('source'))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump({'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'sources': sources, 'component_count': len(uniq), 'components': uniq}, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    findings = []
    if len(uniq) < 100:
        findings.append(gc.finding('SBOM-INCOMPLETE', 'medium', f'SBOM 组件数偏少（{len(uniq)}），可能缺客户端/中间件/语言依赖', evidence=json.dumps(sources, ensure_ascii=False), remediation='补 Maven 坐标、客户端 JS、中间件组件清单'))
    gc.emit('sbom_collect', 'component', 'PASS', findings, summary=json.dumps({'count': len(uniq), 'sources': sources}, ensure_ascii=False))
if __name__ == '__main__':
    main()
