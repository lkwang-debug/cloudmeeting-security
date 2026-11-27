"""应用安全：RCE 相关依赖 CVE 联查（log4j/fastjson/snakeyaml/struts/xstream/shiro 等）。"""
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
SBOM = os.path.join(ROOT, 'reports', 'final', 'gate', 'sbom_merged.json')
RULES = [('log4j-core', '2.17.1', 'Log4Shell/CVE-2021-44228 系'), ('log4j-api', '2.17.1', 'Log4j2 CVE 系'), ('fastjson', '1.2.83', 'CVE-2022-25845 反序列化'), ('snakeyaml', '2.0', '反序列化 RCE 链'), ('commons-collections', '3.2.2', '反序列化 gadget'), ('struts2-core', '2.5.30', 'Struts2 RCE 系'), ('xstream', '1.4.20', 'XStream 反序列化'), ('shiro-core', '1.8.0', 'Shiro 反序列化')]

def vtuple(s):
    return tuple((int(x) if x.isdigit() else 0 for x in re.split('[.\\-]', str(s))))

def evaluate(components):
    out = []
    for c in components:
        name = str(c.get('name') or '')
        ver = str(c.get('version') or '')
        if not ver:
            continue
        low = name.lower()
        for (kw, fixed, note) in RULES:
            hit = kw in low
            if kw == 'fastjson':
                hit = 'libfastjson' not in low and (low.endswith(':fastjson') or low in ('fastjson',) or low.startswith('fastjson-'))
            if hit:
                try:
                    if vtuple(ver) < vtuple(fixed):
                        item = {'component': name, 'version': ver, 'fixed': fixed, 'note': note}
                        if item not in out:
                            out.append(item)
                except Exception:
                    pass
    return out

def main():
    if not os.path.exists(SBOM):
        gc.emit('dependency_rce', 'application', 'BLOCKED', [], blocked_reason='sbom_merged.json 不存在')
        return
    try:
        data = json.load(open(SBOM, encoding='utf-8'))
    except Exception as e:
        gc.emit('dependency_rce', 'application', 'BLOCKED', [], blocked_reason='SBOM 解析失败: ' + str(e)[:120])
        return
    hits = evaluate(data.get('components') or [])
    findings = [gc.finding('RCE-DEP-' + h['component'], 'high', f"RCE 高风险依赖：{h['component']} {h['version']}（{h['note']}）", evidence=json.dumps(h, ensure_ascii=False), remediation=f"升级到 {h['fixed']} 以上") for h in hits]
    gc.emit('dependency_rce', 'application', 'PASS', findings, summary=json.dumps({'hits': len(hits), 'components': hits[:10]}, ensure_ascii=False)[:600])
if __name__ == '__main__':
    main()
