"""把 V8.2 实施报告 Markdown 转成 DOCX（轻量，保留标题/段落/表格文本）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import os
import re
from docx import Document
from docx.oxml.ns import qn
from docx.shared import Pt
ROOT = 'configured-path'
SRC = os.path.join(ROOT, 'reports', 'final', 'V8_v8.2_发布安全门禁_实施报告.md')
OUT = os.path.join(ROOT, 'reports', 'final', 'V8_v8.2_发布安全门禁_实施报告.docx')
doc = Document()
style = doc.styles['Normal']
style.font.name = '微软雅黑'
style.font.size = Pt(10)
style.element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
for line in open(SRC, encoding='utf-8').read().splitlines():
    s = line.rstrip()
    if not s:
        doc.add_paragraph('')
        continue
    if s.startswith('#'):
        level = min(len(s) - len(s.lstrip('#')), 3)
        text = s.lstrip('#').strip()
        p = doc.add_heading(text, level=level)
        for r in p.runs:
            r.font.name = '微软雅黑'
            r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    elif s.startswith('|'):
        doc.add_paragraph(s)
    elif re.match('^\\d+\\.\\s|^-\\s', s):
        doc.add_paragraph(s, style='List Bullet')
    else:
        doc.add_paragraph(s)
doc.save(OUT)
print('docx:', OUT)
