"""V8 P1 覆盖补齐：hst-meeting 容器内 Java 依赖 SBOM + 已知 CVE 规则匹配（只读）。
输出 reports/final/java_sbom/java_dependencies.json + JAVA_CVE_REPORT.md
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import time
import paramiko
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'reports', 'final', 'java_sbom')
os.makedirs(OUT, exist_ok=True)
RULES = [{'name': 'log4j-core', 're': '^log4j-core-(\\d+\\.\\d+(?:\\.\\d+)?)(?:\\.jar)?$', 'vuln': 'Log4Shell CVE-2021-44228 等', 'bad_max': '2.17.0'}, {'name': 'log4j-api', 're': '^log4j-api-(\\d+\\.\\d+(?:\\.\\d+)?)', 'vuln': 'Log4j2 系列 CVE', 'bad_max': '2.17.0'}, {'name': 'fastjson', 're': '^fastjson-(\\d+\\.\\d+(?:\\.\\d+)?)', 'vuln': 'CVE-2022-25845 反序列化', 'bad_max': '1.2.83'}, {'name': 'jackson-databind', 're': '^jackson-databind-(\\d+\\.\\d+(?:\\.\\d+)?)', 'vuln': '多态反序列化 CVE 系列', 'bad_max': '2.13.4.2'}, {'name': 'shiro-core', 're': '^shiro-core-(\\d+\\.\\d+(?:\\.\\d+)?)', 'vuln': 'Shiro 反序列化/路径绕过 CVE', 'bad_max': '1.8.0'}, {'name': 'commons-collections', 're': '^commons-collections-(\\d+\\.\\d+(?:\\.\\d+)?)', 'vuln': '反序列化 gadget', 'bad_max': '3.2.2'}, {'name': 'spring-core', 're': '^spring-core-(\\d+\\.\\d+(?:\\.\\d+)?)', 'vuln': 'Spring4Shell 等（需结合 webmvc）', 'bad_max': '5.3.18'}, {'name': 'xstream', 're': '^xstream-(\\d+\\.\\d+(?:\\.\\d+)?)', 'vuln': 'XStream 反序列化 CVE', 'bad_max': '1.4.20'}, {'name': 'snakeyaml', 're': '^snakeyaml-(\\d+\\.\\d+(?:\\.\\d+)?)', 'vuln': 'SnakeYAML 反序列化 CVE', 'bad_max': '2.0'}, {'name': 'bcprov-jdk15on', 're': '^bcprov-jdk15on-(\\d+\\.\\d+(?:\\.\\d+)?)', 'vuln': 'BouncyCastle CVE 系列', 'bad_max': '1.69'}]

def vtuple(s):
    out = []
    for p in re.split('[.\\-]', s):
        out.append(int(p) if p.isdigit() else 0)
    return tuple(out)

def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)
    cmd = "find /hst -name '*.jar' 2>/dev/null | grep -v '/jdk' | head -800"
    (i, o, e) = c.exec_command(cmd, timeout=120)
    jars = sorted(set((x.strip() for x in o.read().decode('utf-8', 'replace').splitlines() if x.strip())))
    c.close()
    deps = []
    for p in jars:
        fn = os.path.basename(p)
        deps.append({'jar': fn, 'path': p})
    findings = []
    for d in deps:
        base = re.sub('\\.jar$', '', d['jar'])
        for rule in RULES:
            m = re.match(rule['re'], base)
            if not m:
                continue
            ver = m.group(1)
            if vtuple(ver) < vtuple(rule['bad_max']):
                findings.append({'component': rule['name'], 'version': ver, 'jar': d['jar'], 'vuln': rule['vuln'], 'confidence': 'filename-based'})
            break
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'container': 'hst-meeting', 'jar_count': len(deps), 'dependencies': deps[:2000], 'findings': findings, 'note': '基于容器内 jar 文件名/版本匹配，需结合 Maven 坐标与厂商补丁确认'}
    json.dump(result, open(os.path.join(OUT, 'java_dependencies.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    lines = ['# Java 依赖 SBOM / CVE 候选（hst-meeting 容器）', '', f"- 时间：{result['generated_at']}", f'- jar 总数：{len(deps)}', f'- 命中规则：{len(findings)}', '', '| 组件 | 版本 | 规则 CVE | jar |', '|---|---|---|---|']
    for f in findings:
        lines.append(f"| {f['component']} | {f['version']} | {f['vuln']} | {f['jar']} |")
    lines += ['', '> 文件名/版本推断，属候选；需 Maven 坐标与厂商补丁确认；未命中不代表安全。']
    open(os.path.join(OUT, 'JAVA_CVE_REPORT.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    print('jars:', len(deps), 'findings:', len(findings), '->', OUT)
if __name__ == '__main__':
    main()
