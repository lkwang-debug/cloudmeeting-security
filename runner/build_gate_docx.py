"""把 RELEASE_GATE.md 转成 DOCX（门禁报告交付版）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import os
from docx import Document
from docx.oxml.ns import qn
from docx.shared import Pt
ROOT = 'configured-path'
SRC = os.path.join(ROOT, 'reports', 'final', 'gate', 'RELEASE_GATE.md')
OUT = os.path.join(ROOT, 'reports', 'final', 'gate', 'RELEASE_GATE.docx')
doc = Document()
style = doc.styles['Normal']
style.font.name = '微软雅黑'
style.font.size = Pt(9)
style.element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
for line in open(SRC, encoding='utf-8').read().splitlines():
    s = line.rstrip()
    if not s:
        doc.add_paragraph('')
        continue
    if s.startswith('#'):
        level = min(len(s) - len(s.lstrip('#')), 3)
        p = doc.add_heading(s.lstrip('#').strip(), level=level)
        for r in p.runs:
            r.font.name = '微软雅黑'
            r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    else:
        doc.add_paragraph(s)
doc.save(OUT)
print('docx:', OUT)
