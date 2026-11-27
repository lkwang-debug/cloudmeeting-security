"""批量提取客户漏扫报告文本（docx/xlsx/xls/pdf）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import os
import sys
from docx import Document
import openpyxl
try:
    import xlrd
except Exception:
    xlrd = None
try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None
ROOT = 'configured-path'
SRC = os.path.join(ROOT, 'sources', '漏扫', '漏扫')
OUT = os.path.join(ROOT, 'reports', 'final', 'customer_reports')
os.makedirs(OUT, exist_ok=True)

def docx_text(p):
    d = Document(p)
    lines = [x.text.strip() for x in d.paragraphs if x.text.strip()]
    for (ti, t) in enumerate(d.tables):
        lines.append(f'[TABLE {ti}]')
        for r in t.rows:
            vals = []
            for c in r.cells:
                v = c.text.strip().replace('\n', ' ')
                if v and (not vals or vals[-1] != v):
                    vals.append(v)
            if vals:
                lines.append(' | '.join(vals))
    return '\n'.join(lines)

def xlsx_text(p):
    wb = openpyxl.load_workbook(p, data_only=True, read_only=True)
    lines = []
    for ws in wb.worksheets:
        lines.append(f'[SHEET {ws.title}]')
        for row in ws.iter_rows(values_only=True):
            vals = [str(v).strip().replace('\n', ' ') for v in row if v not in (None, '')]
            if vals:
                lines.append(' | '.join(vals))
    wb.close()
    return '\n'.join(lines)

def xls_text(p):
    if xlrd is None:
        return ''
    book = xlrd.open_workbook(p)
    lines = []
    for sh in book.sheets():
        lines.append(f'[SHEET {sh.name}]')
        for ri in range(sh.nrows):
            vals = [str(sh.cell_value(ri, ci)).strip() for ci in range(sh.ncols) if str(sh.cell_value(ri, ci)).strip()]
            if vals:
                lines.append(' | '.join(vals))
    return '\n'.join(lines)

def pdf_text(p):
    if PdfReader is None:
        return ''
    r = PdfReader(p)
    lines = []
    for (i, pg) in enumerate(r.pages):
        try:
            lines.append(pg.extract_text() or '')
        except Exception:
            lines.append('')
    return '\n'.join(lines)

def main():
    report = []
    combined = []
    for fn in sorted(os.listdir(SRC)):
        p = os.path.join(SRC, fn)
        if not os.path.isfile(p) or fn == '.DS_Store':
            continue
        ext = os.path.splitext(fn)[1].lower()
        try:
            if ext == '.docx':
                text = docx_text(p)
            elif ext == '.xlsx':
                text = xlsx_text(p)
            elif ext == '.xls':
                text = xls_text(p)
            elif ext == '.pdf':
                text = pdf_text(p)
            else:
                text = ''
            out = os.path.join(OUT, fn + '.txt')
            open(out, 'w', encoding='utf-8').write(text)
            report.append({'file': fn, 'chars': len(text), 'ok': bool(text.strip())})
            if text.strip():
                combined.append(f'\n\n########## {fn} ##########\n{text}')
        except Exception as e:
            report.append({'file': fn, 'chars': 0, 'error': str(e)[:160]})
    open(os.path.join(OUT, '_ALL.txt'), 'w', encoding='utf-8').write('\n'.join(combined))
    import json
    json.dump(report, open(os.path.join(OUT, '_index.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    for r in report:
        print(r['file'], r.get('chars'), r.get('error', ''))
    print('total files', len(report), 'text files', sum((1 for r in report if r.get('ok'))))
if __name__ == '__main__':
    main()
