"""生成客户版发版前扫描摘要（Markdown/DOCX 由 build_customer_docx 转换）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, 'reports', 'final', 'gate', 'gate_result.json')
EXT = os.path.join(ROOT, 'reports', 'final', 'gate', 'GATE_EXTERNAL_COMPARE.md')
OUT = os.path.join(ROOT, 'reports', 'final', 'gate', 'CUSTOMER_RELEASE_GATE.md')

def main():
    g = json.load(open(GATE, encoding='utf-8'))
    cfg = yaml.safe_load(open(os.path.join(ROOT, 'configs', 'release_gate.yaml'), encoding='utf-8'))
    lines = ['# 云会议产品发版前安全扫描报告（客户版摘要）', '', f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M')}", '- 扫描方式：自动化安全门禁 + AppScan 报告对比（报告模式，不阻断发版）', f"- 总体结论：**{g['overall']}**", '', '## 一、四类结果', '', '| 类别 | 状态 | 阻断项 |', '|---|---|---|']
    for (k, c) in g['categories'].items():
        lines.append(f"| {c['title']} | {c['status']} | {len(c['blocking_findings'])} |")
    lines += ['', '## 二、主要问题（按严重性）', '']
    seen = set()
    rows = []
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    for (k, c) in g['categories'].items():
        for f in c['findings']:
            if f.get('supplemental'):
                continue
            key = (str(f.get('severity')), str(f.get('title')))
            if key in seen:
                continue
            seen.add(key)
            rows.append((k, f))
    rows.sort(key=lambda x: order.get(str(x[1].get('severity')).lower(), 9))
    for (k, f) in rows[:30]:
        lines.append(f"- [{f.get('severity')}] {str(f.get('title'))[:120]}")
    lines += ['', '## 三、AppScan 客户视角对比', '']
    if os.path.exists(EXT):
        for line in open(EXT, encoding='utf-8'):
            if line.startswith('- ') or '覆盖' in line:
                lines.append(line.rstrip())
    lines += ['', '## 四、说明', '', '- 本报告为发版前内部自检结果，不代表客户商用扫描器最终结果；', '- 高危/阻断项建议修复后再发版；', '- 详细证据见 gate_result.json、CHECK_MATRIX.md、GATE_EXTERNAL_COMPARE.md。']
    open(OUT, 'w', encoding='utf-8').write('\n'.join(lines))
    print('written:', OUT)
if __name__ == '__main__':
    main()
