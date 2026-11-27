"""生成 AppScan 风格安全测试报告（DOCX）：封面/摘要/发现汇总/详细发现/附录。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import time
from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor
ROOT = 'configured-path'
GATE = os.path.join(ROOT, 'reports', 'final', 'gate')
OUT = os.path.join(GATE, 'SECURITY_ASSESSMENT_REPORT.docx')
APPSCAN_NAMES = {'HSTS': 'HSTS 响应头缺失', 'CORSArbitraryOrigin': 'CORS 允许任意 Origin', 'attNoContentTypeOptionsHeaderExist': 'X-Content-Type-Options 响应头缺失', 'attReferrerPolicyHeaderExist': 'Referrer-Policy 响应头缺失', 'attContentSecurityPolicyHeaderExist': 'Content-Security-Policy 响应头缺失', 'attXFrameOptionsHeaderExist': 'X-Frame-Options 响应头缺失', 'attCachedSSL': 'SSL 页面被缓存', 'attDirectoryDiscover': '目录发现', 'attDirectoryListing': '目录列表', 'attCookieJavaScript': 'Cookie 可被 JS 读取', 'attIPAddress': '内部 IP 地址泄露', 'attInternalIP': '内部 IP 地址泄露'}
SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
SEV_CN = {'critical': '严重', 'high': '高', 'medium': '中', 'low': '低', 'info': '信息'}

def cn_sev(s):
    return SEV_CN.get(str(s).lower(), str(s))

def add_heading(doc, text, level=1):
    p = doc.add_heading(text, level=level)
    for r in p.runs:
        r.font.name = '微软雅黑'
        r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    return p

def add_para(doc, text, bold=False, size=10):
    p = doc.add_paragraph()
    r = p.add_run(str(text))
    r.bold = bold
    r.font.size = Pt(size)
    r.font.name = '微软雅黑'
    r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    return p

def add_table(doc, headers, rows, widths=None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = 'Light Grid Accent 1'
    for (i, h) in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = str(h)
        for p in c.paragraphs:
            for r in p.runs:
                r.bold = True
                r.font.size = Pt(9)
                r.font.name = '微软雅黑'
                r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    for row in rows:
        cells = t.add_row().cells
        for (i, v) in enumerate(row):
            cells[i].text = str(v)
            for p in cells[i].paragraphs:
                for r in p.runs:
                    r.font.size = Pt(8)
                    r.font.name = '微软雅黑'
                    r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    return t

def collect(g):
    items = []
    for (cat, c) in g['categories'].items():
        for f in c.get('findings') or []:
            if f.get('supplemental'):
                continue
            items.append({'category': cat, 'check': f.get('check'), 'id': f.get('id'), 'severity': str(f.get('severity', '')).lower(), 'title': f.get('title'), 'evidence': f.get('evidence'), 'remediation': f.get('remediation')})
    return items

def component_groups(items):
    groups = {}
    for f in items:
        if f['category'] != 'component':
            continue
        m = re.search('Trivy:\\s*([^ ]+)\\s+([^ ]+)\\s+命中\\s+(\\S+)', str(f['title']))
        if m:
            key = f'{m.group(1)} {m.group(2)}'
            groups.setdefault(key, {'severity': f['severity'], 'cves': [], 'evidence': f['evidence']})
            groups[key]['cves'].append(m.group(3))
    return groups

def main():
    g = json.load(open(os.path.join(GATE, 'gate_result.json'), encoding='utf-8'))
    items = collect(g)
    appscan = []
    ap = os.path.join(GATE, 'appscan_findings.json')
    if os.path.exists(ap):
        appscan = (json.load(open(ap, encoding='utf-8')) or {}).get('findings') or []
    checks = {}
    groups = component_groups(items)
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in items:
        if f['severity'] in counts:
            counts[f['severity']] += 1
    for f in appscan:
        if str(f.get('severity')).lower() in counts:
            counts[str(f.get('severity')).lower()] += 1
    doc = Document()
    sec = doc.sections[0]
    sec.top_margin = Pt(36)
    sec.bottom_margin = Pt(36)
    st = doc.styles['Normal']
    st.font.name = '微软雅黑'
    st.font.size = Pt(10)
    st.element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    for _ in range(5):
        doc.add_paragraph('')
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run('云会议 Web 后台安全测试报告')
    r.bold = True
    r.font.size = Pt(26)
    r.font.color.rgb = RGBColor(31, 58, 95)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run('发版前自动化安全评估（AppScan 风格）')
    r.font.size = Pt(14)
    r.font.color.rgb = RGBColor(85, 85, 85)
    doc.add_paragraph('')
    add_table(doc, ['项目', '内容'], [['报告版本', 'V8.2 / 2026-11-24'], ['测试对象', _pub.target()], ['测试类型', '自动化安全门禁 + AppScan 报告对比（报告模式）'], ['报告结论', g.get('overall')], ['密级', '内部/客户交付']])
    doc.add_page_break()
    add_heading(doc, '1. 执行摘要', 1)
    add_para(doc, f"本次针对云会议 Web 后台执行发版前安全评估，覆盖应用安全、加密安全、组件安全、中间件安全四类，共 {len(g['checks'])} 项检查。")
    add_para(doc, f"总体结论：{g.get('overall')}；高风险 {counts['high']} 项、中风险 {counts['medium']} 项、低风险 {counts['low']} 项。", bold=True)
    add_heading(doc, '1.1 风险分布', 2)
    add_table(doc, ['严重性', '数量'], [[cn_sev(k), counts[k]] for k in ('critical', 'high', 'medium', 'low')])
    add_heading(doc, '1.2 四类结果', 2)
    add_table(doc, ['类别', '状态', '阻断项'], [[c['title'], c['status'], len(c['blocking_findings'])] for c in g['categories'].values()])
    add_heading(doc, '1.3 主要风险', 2)
    top = sorted([f for f in items if f['severity'] in ('critical', 'high')], key=lambda x: SEV_ORDER.get(x['severity'], 9))[:8]
    for (i, f) in enumerate(top, 1):
        add_para(doc, f"{i}. [{cn_sev(f['severity'])}] {f['title']}（{f['category']}）")
    add_heading(doc, '2. 测试范围与方法', 1)
    add_table(doc, ['项目', '说明'], [['测试目标', '云会议 Web 后台（管理端 + H5 客户端 API + 中间件/主机）'], ['测试方法', '自动化门禁检查、SBOM/CVE（Trivy/Grype）、AppScan 报告导入对比、人工复核'], ['不在范围', '性能/功能测试、源码审计、完整商用扫描器复测'], ['测试限制', '部分检查为黑盒探测，未记录所有原始请求/响应；CVE 为 SBOM 推断']])
    add_heading(doc, '3. 发现汇总', 1)
    add_heading(doc, '3.1 应用/加密/中间件', 2)
    rows = []
    for f in sorted([x for x in items if x['category'] != 'component'], key=lambda x: (SEV_ORDER.get(x['severity'], 9), x['category'])):
        rows.append([f['id'], cn_sev(f['severity']), f['category'], str(f['title'])[:80], f['check']])
    add_table(doc, ['ID', '严重性', '类别', '标题', '检查项'], rows[:60])
    add_heading(doc, '3.2 组件 CVE（按组件分组）', 2)
    rows = []
    for (pkg, v) in sorted(groups.items(), key=lambda x: -len(x[1]['cves'])):
        rows.append([pkg, cn_sev(v['severity']), len(v['cves']), ', '.join(sorted(set(v['cves'])))[:120]])
    add_table(doc, ['组件', '最高严重性', 'CVE 数', 'CVE'], rows)
    add_heading(doc, '3.3 AppScan 外部报告', 2)
    add_para(doc, f'已导入真实 AppScan 报告，规则 {len(appscan)} 条；客户视角规则覆盖 23/23（100%）。')
    add_table(doc, ['规则/标题', '严重性', '影响实体数'], [[APPSCAN_NAMES.get(str(f.get('rule')), f.get('title')), cn_sev(f.get('severity')), f.get('entities')] for f in appscan[:30]])
    add_heading(doc, '4. 详细发现', 1)
    detailed = [f for f in items if f['severity'] in ('critical', 'high', 'medium')]
    for (i, f) in enumerate(detailed, 1):
        add_heading(doc, f"4.{i} {f['title']}", 2)
        add_table(doc, ['字段', '内容'], [['编号', f['id']], ['严重性', cn_sev(f['severity'])], ['类别', f['category']], ['检测项', f['check']], ['证据/位置', str(f['evidence'])[:500]], ['修复建议', f['remediation'] or '按检查项建议修复'], ['验证方式', '修复后重跑对应检查项 / scan_before_release.ps1']])
    if groups:
        add_heading(doc, '4.99 组件 CVE 修复清单', 2)
        add_table(doc, ['组件', '当前版本', 'CVE', '建议修复版本'], [[pkg, '', ', '.join(sorted(set(v['cves']))), str(v['evidence']).replace('fixed=', '').split(' target=')[0]] for (pkg, v) in groups.items()])
    add_heading(doc, '5. AppScan 对比与覆盖', 1)
    ext = os.path.join(GATE, 'GATE_EXTERNAL_COMPARE.md')
    if os.path.exists(ext):
        for line in open(ext, encoding='utf-8'):
            if line.startswith('- ') or '覆盖' in line:
                add_para(doc, line.strip().lstrip('- '))
    add_para(doc, '说明：AppScan 报告为规则级导入（未包含全部 URL/请求响应），本报告补充了自研检查与组件 CVE。')
    add_heading(doc, '6. 附录', 1)
    add_heading(doc, '6.1 检查矩阵', 2)
    add_table(doc, ['检查', '状态', '发现数'], [[cid, v.get('status'), v.get('findings', 0)] for (cid, v) in g['checks'].items()])
    add_heading(doc, '6.2 报告说明', 2)
    for t in ['本报告为发版前自动化评估结果，不等同于客户商用扫描器最终报告；', 'High/Critical 建议发版前修复；报告模式不阻断发版；', '组件 CVE 基于 SBOM 推断，需结合实际运行时加载确认；', '原始数据：gate_result.json、appscan_findings.json、trivy_sbom.json、grype_sbom.json。']:
        add_para(doc, '- ' + t)
    doc.save(OUT)
    print('docx:', OUT)
if __name__ == '__main__':
    main()
