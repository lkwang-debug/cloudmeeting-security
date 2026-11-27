"""V8.2 发布前安全门禁：执行检查 → 归一化证据 → 四类门禁评估 → RELEASE_GATE 报告。

用法：
  python runner/release_gate.py --profile quick
  python runner/release_gate.py --profile release
退出码：0=通过/带豁免通过，1=失败，2=阻塞。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
DEFAULT_CONFIG = os.path.join(ROOT, 'configs', 'release_gate.yaml')
MATRIX = os.path.join(ROOT, 'knowledge', 'gate_matrix.yaml')
EXCEPTIONS = os.path.join(ROOT, 'configs', 'gate_exceptions.yaml')
OUT_DIR = os.path.join(ROOT, 'reports', 'final', 'gate')
OUT_JSON = os.path.join(OUT_DIR, 'gate_result.json')
OUT_MD = os.path.join(OUT_DIR, 'RELEASE_GATE.md')

def load_yaml(path):
    if not os.path.exists(path):
        return {}
    return yaml.safe_load(open(path, encoding='utf-8')) or {}

def load_exceptions():
    data = load_yaml(EXCEPTIONS)
    today = time.strftime('%Y-%m-%d')
    out = []
    for e in data.get('exceptions') or []:
        if e.get('expires') and str(e['expires']) < today:
            continue
        out.append(e)
    return out

def run_checks(cfg, profile, evidence_dir):
    checks = cfg.get('checks') or {}
    plan = (cfg.get('profiles') or {}).get(profile) or []
    os.makedirs(evidence_dir, exist_ok=True)
    env = dict(os.environ)
    env['GATE_EVIDENCE_DIR'] = evidence_dir
    env['GATE_HTTP_EVIDENCE'] = '1'
    results = {}
    for cid in plan:
        meta = checks.get(cid)
        if not meta:
            results[cid] = {'status': 'ERROR', 'blocked_reason': 'check not configured', 'findings': []}
            continue
        cmd = [PY, os.path.join(ROOT, meta['cmd'])]
        env['GATE_CHECK_ID'] = cid
        shutil.rmtree(os.path.join(evidence_dir, 'http', cid), ignore_errors=True)
        t0 = time.time()
        try:
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=int(meta.get('timeout', 300)), env=env)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc = 124
            p = None
        ev_path = os.path.join(evidence_dir, cid + '.json')
        if os.path.exists(ev_path):
            try:
                ev = json.load(open(ev_path, encoding='utf-8'))
            except Exception as e:
                ev = {'check_id': cid, 'status': 'ERROR', 'findings': [], 'blocked_reason': f'bad evidence: {e}'}
        else:
            ev = {'check_id': cid, 'status': 'ERROR', 'findings': [], 'blocked_reason': 'no evidence file (rc=%s)' % rc}
        ev['duration'] = round(time.time() - t0, 1)
        ev['returncode'] = rc
        if p is not None:
            ev['stdout_tail'] = (p.stdout or '')[-500:]
            ev['stderr_tail'] = (p.stderr or '')[-300:]
        results[cid] = ev
        print(f"[{cid}] {ev.get('status')} rc={rc} {ev['duration']}s")
    return results

def match_exception(f, cid, exceptions):
    keys = {f.get('id', ''), cid, f"{cid}:{f.get('title', '')}"}
    for e in exceptions:
        eid = str(e.get('id', ''))
        if eid and (eid in keys or eid in f.get('id', '') or eid in f.get('title', '')):
            return e
    return None

def evaluate(cfg, results, exceptions):
    categories_cfg = cfg.get('categories') or {}
    cats = {}
    all_excepted = []
    for (cat, rules) in categories_cfg.items():
        required = rules.get('required') or []
        fail_sev = set(rules.get('fail_severities') or ['critical', 'high'])
        cat_checks = {cid: r for (cid, r) in results.items() if (cfg.get('checks', {}).get(cid, {}) or {}).get('category') == cat}
        findings = []
        for (cid, res) in cat_checks.items():
            if res.get('status') == 'ERROR':
                findings.append({'id': f'{cid}:error', 'severity': 'high', 'title': f'{cid} 执行错误/超时', 'evidence': res.get('blocked_reason', ''), 'remediation': '修复检查依赖后重跑'})
            for f in res.get('findings') or []:
                f2 = dict(f)
                f2['check'] = cid
                if not (cfg.get('checks', {}).get(cid, {}) or {}).get('blocking', True):
                    f2['supplemental'] = True
                exc = match_exception(f2, cid, exceptions)
                if exc:
                    f2['excepted'] = exc
                    all_excepted.append(f2)
                findings.append(f2)
        seen = {}
        dedup = []
        for f in findings:
            cid = re.sub('^(GRYPE|TRIVY)-', '', str(f.get('id', '')))
            key = cid or (f.get('check', ''), f.get('title', ''))
            if key in seen:
                seen[key].setdefault('also_reported_by', []).append(f.get('check', ''))
                continue
            seen[key] = f
            dedup.append(f)
        findings = dedup
        blocking = [f for f in findings if not f.get('excepted') and (not f.get('supplemental')) and (f.get('severity') in fail_sev)]
        blocked_checks = [cid for cid in required if cid not in results or results.get(cid, {}).get('status') == 'BLOCKED']
        status = 'PASS'
        if blocking:
            status = 'FAIL'
        elif blocked_checks and rules.get('blocked_is_failure'):
            status = 'BLOCKED'
        elif blocked_checks:
            status = 'BLOCKED'
        elif any((f.get('excepted') for f in findings)):
            status = 'PASS_WITH_EXCEPTIONS'
        elif findings:
            status = 'PASS_WITH_FINDINGS'
        cats[cat] = {'title': rules.get('title') or cat, 'status': status, 'findings': findings, 'blocking_findings': blocking, 'blocked_checks': blocked_checks, 'checks': cat_checks}
    overall = 'PASS'
    if any((c['status'] == 'FAIL' for c in cats.values())):
        overall = 'FAIL'
    elif any((c['status'] == 'BLOCKED' for c in cats.values())):
        overall = 'BLOCKED'
    elif all_excepted or any((c['status'] == 'PASS_WITH_EXCEPTIONS' for c in cats.values())):
        overall = 'PASS_WITH_EXCEPTIONS'
    elif any((c['status'] == 'PASS_WITH_FINDINGS' for c in cats.values())):
        overall = 'PASS_WITH_FINDINGS'
    return (cats, overall, all_excepted)

def matrix_summary():
    m = load_yaml(MATRIX)
    items = []
    for r in (m.get('reports') or {}).values():
        items += r.get('items') or []
    auto = [i for i in items if i.get('level') == 'auto']
    semi = [i for i in items if i.get('level') == 'semi']
    manual = [i for i in items if i.get('level') in ('manual', 'blocked')]
    return {'report_items': len(items), 'auto': len(auto), 'semi': len(semi), 'manual': len(manual), 'coverage_auto_pct': round(len(auto) / len(items) * 100, 1) if items else 0, 'coverage_auto_semi_pct': round((len(auto) + len(semi)) / len(items) * 100, 1) if items else 0}

def write_outputs(cfg, profile, results, cats, overall, exceptions):
    os.makedirs(OUT_DIR, exist_ok=True)
    payload = {'schema_version': 'v8.2', 'profile': profile, 'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'overall': overall, 'matrix': matrix_summary(), 'categories': cats, 'exceptions': exceptions, 'checks': {cid: {'status': r.get('status'), 'summary': r.get('summary'), 'blocked_reason': r.get('blocked_reason'), 'findings': len(r.get('findings') or []), 'duration': r.get('duration')} for (cid, r) in results.items()}}
    json.dump(payload, open(OUT_JSON, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    hist = os.path.join(OUT_DIR, 'history')
    os.makedirs(hist, exist_ok=True)
    snap = os.path.join(hist, time.strftime('%Y%m%d-%H%M%S') + '.json')
    json.dump(payload, open(snap, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    snaps = sorted(os.listdir(hist))
    for old in snaps[:-50]:
        try:
            os.remove(os.path.join(hist, old))
        except Exception:
            pass
    lines = ['# 发布前安全门禁报告（V8.2）', '', f"- 时间：{payload['generated_at']}", f'- Profile：{profile}', f'- 结论：**{overall}**', f"- 客户报告映射：{payload['matrix']['report_items']} 项，自动 {payload['matrix']['auto']}，半自动 {payload['matrix']['semi']}，人工/阻塞 {payload['matrix']['manual']}", '', '## 四类门禁', '', '| 类别 | 状态 | 阻断项 | 阻塞检查 |', '|---|---|---|---|']
    for (cat, c) in cats.items():
        lines.append(f"| {c['title']} | {c['status']} | {len(c['blocking_findings'])} | {', '.join(c['blocked_checks']) or '-'} |")
    lines += ['', '## 发现项（阻断）', '']
    any_block = False
    for (cat, c) in cats.items():
        for f in c['blocking_findings']:
            any_block = True
            lines.append(f"- [{c['title']}] {f.get('severity', '')} {f.get('title', '')} (check={f.get('check')}) 证据：{f.get('evidence', '')}")
    if not any_block:
        lines.append('- 无阻断项（或均已豁免）')
    lines += ['', '## 检查明细', '', '| 检查 | 状态 | 发现数 | 说明 |', '|---|---|---|---|']
    for (cid, r) in results.items():
        lines.append(f"| {cid} | {r.get('status')} | {len(r.get('findings') or [])} | {(r.get('summary') or r.get('blocked_reason') or '')[:80]} |")
    lines += ['', '## 说明', '', '本门禁是研发内部预检，不替代客户商用扫描器；目标为高危提前清零、组件/加密清单齐全。', '状态：PASS 通过；PASS_WITH_EXCEPTIONS 仅有已豁免项；PASS_WITH_FINDINGS 有中低风险发现；FAIL 有阻断项；BLOCKED 缺少必要环境/检查。']
    open(OUT_MD, 'w', encoding='utf-8').write('\n'.join(lines))
    return payload

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', default='quick', choices=['quick', 'release'])
    ap.add_argument('--config', default=DEFAULT_CONFIG)
    ap.add_argument('--evidence-dir', default=os.path.join(OUT_DIR, 'evidence'))
    args = ap.parse_args()
    cfg = load_yaml(args.config)
    exceptions = load_exceptions()
    results = run_checks(cfg, args.profile, args.evidence_dir)
    (cats, overall, excepted) = evaluate(cfg, results, exceptions)
    payload = write_outputs(cfg, args.profile, results, cats, overall, exceptions)
    print('\nOVERALL:', overall)
    print('REPORT:', OUT_JSON, OUT_MD)
    if overall == 'FAIL':
        return 1
    if overall == 'BLOCKED':
        return 2
    return 0
if __name__ == '__main__':
    sys.exit(main())
