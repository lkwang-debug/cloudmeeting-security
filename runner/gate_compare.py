"""V8.2 门禁趋势与整改清单：
- 读取最近两次门禁快照，输出新增/已修复/仍存在；
- 生成 REMEDIATION.md（按类别/严重性，含证据与修复建议入口）。
用法：python runner/gate_compare.py
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import csv
import datetime
import json
import os
import time
import yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_DIR = os.path.join(ROOT, 'reports', 'final', 'gate')
HIST = os.path.join(GATE_DIR, 'history')

def finding_key(f):
    return (f.get('check', ''), f.get('id', ''), f.get('title', ''))

def load_snapshots():
    if not os.path.isdir(HIST):
        return []
    files = sorted((f for f in os.listdir(HIST) if f.endswith('.json')))
    out = []
    for f in files[-2:]:
        try:
            out.append(json.load(open(os.path.join(HIST, f), encoding='utf-8')))
        except Exception:
            pass
    return out

def main():
    snaps = load_snapshots()
    current = snaps[-1] if snaps else None
    previous = snaps[0] if len(snaps) > 1 else None
    if not current:
        print('no gate snapshot; run release_gate.py first')
        return
    cur_f = {}
    for (cat, c) in (current.get('categories') or {}).items():
        for f in c.get('findings') or []:
            cur_f[finding_key(f)] = (cat, f)
    prev_f = {}
    if previous:
        for (cat, c) in (previous.get('categories') or {}).items():
            for f in c.get('findings') or []:
                prev_f[finding_key(f)] = (cat, f)
    new = [v for (k, v) in cur_f.items() if k not in prev_f]
    fixed = [v for (k, v) in prev_f.items() if k not in cur_f]
    still = [v for (k, v) in cur_f.items() if k in prev_f]
    trend = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'current_overall': current.get('overall'), 'previous_overall': previous.get('overall') if previous else None, 'new_findings': [{'category': c, **f} for (c, f) in new], 'fixed_findings': [{'category': c, **f} for (c, f) in fixed], 'still_open': [{'category': c, **f} for (c, f) in still]}
    json.dump(trend, open(os.path.join(GATE_DIR, 'gate_trend.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    policy = {}
    pp = os.path.join(ROOT, 'configs', 'remediation_policy.yaml')
    if os.path.exists(pp):
        policy = yaml.safe_load(open(pp, encoding='utf-8')) or {}
    owner_map = policy.get('category_owner') or {}
    default_owner = policy.get('default_owner', '研发')
    sla = policy.get('sla_days') or {}
    rows = []
    for (c, f) in new + still:
        sev = str(f.get('severity', '')).lower()
        days = int(sla.get(sev, 30))
        due = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
        rows.append({'category': c, 'severity': sev, 'title': f.get('title', ''), 'evidence': f.get('evidence', ''), 'owner': owner_map.get(c, default_owner), 'due': due, 'status': 'OPEN'})
    if rows:
        with open(os.path.join(GATE_DIR, 'REMEDIATION.csv'), 'w', newline='', encoding='utf-8-sig') as fh:
            w = csv.DictWriter(fh, fieldnames=['category', 'severity', 'title', 'evidence', 'owner', 'due', 'status'])
            w.writeheader()
            w.writerows(rows)
    lines = ['# 门禁趋势与整改清单', '', f"- 时间：{trend['generated_at']}", f"- 本次总体：**{trend['current_overall']}**；上次：{trend['previous_overall']}", f'- 新增：{len(new)}；已修复：{len(fixed)}；仍存在：{len(still)}', '', '## 新增/仍存在（需整改）', '', '| 类别 | 严重性 | 标题 | 责任人 | 截止日期 | 证据 |', '|---|---|---|---|---|---|']
    for r in rows:
        lines.append(f"| {r['category']} | {r['severity']} | {str(r['title'])[:70]} | {r['owner']} | {r['due']} | {str(r['evidence'])[:60]} |")
    lines += ['', '## 已修复', '']
    if fixed:
        for (c, f) in fixed:
            lines.append(f"- {c}: {f.get('title')}")
    else:
        lines.append('- 无（首次运行或与上次相同）')
    open(os.path.join(GATE_DIR, 'REMEDIATION.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    print(json.dumps({'new': len(new), 'fixed': len(fixed), 'still': len(still)}, ensure_ascii=False))
if __name__ == '__main__':
    main()
