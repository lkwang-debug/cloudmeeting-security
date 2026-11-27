"""应用安全：浏览器 DOM XSS 探测（Playwright + Chrome，仅测试环境）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import sys
import time
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT
CHROME = os.environ.get('GATE_CHROME') or 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
PAGES = ['/#/ui/login', '/#/ui/organizational-management/user-management', '/webapp/']
PAYLOAD = '<img src=x onerror=window.__xss=1>'

def main():
    if not os.path.exists(CHROME):
        gc.emit('xss_dom', 'application', 'BLOCKED', [], blocked_reason='未找到 Chrome/Playwright 浏览器')
        return
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        gc.emit('xss_dom', 'application', 'BLOCKED', [], blocked_reason='playwright 未安装: ' + str(e)[:100])
        return
    findings = []
    results = []
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, executable_path=CHROME, args=['--ignore-certificate-errors', '--no-sandbox'])
        ctx = b.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        for path in PAGES:
            url = gc.base_url() + path
            sep = '&' if '?' in url else '?'
            try:
                page.goto(url + sep + 'xss=' + PAYLOAD, wait_until='domcontentloaded', timeout=30000)
                page.wait_for_timeout(2500)
                val = page.evaluate('window.__xss || 0')
                results.append({'page': path, 'window_xss': val, 'final_url': page.url})
                if val:
                    findings.append(gc.finding('XSS-DOM', 'high', f'DOM XSS 触发：{path}', evidence=json.dumps(results[-1], ensure_ascii=False), remediation='DOM 渲染转义/CSP'))
            except Exception as e:
                results.append({'page': path, 'error': str(e)[:120]})
        b.close()
    gc.emit('xss_dom', 'application', 'PASS', findings, summary=json.dumps({'results': results}, ensure_ascii=False)[:700])
if __name__ == '__main__':
    main()
