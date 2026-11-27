"""应用安全：浏览器/UI 存储型 XSS 验证（封装 checks/xss_room_ui.py）。
创建测试房间 → 管理后台 UI 渲染 → DOM 检查；无头浏览器需 playwright。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import subprocess
import sys
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT
RESULT = os.path.join(ROOT, 'reports', 'final', 'xss_room_ui.json')

def system_python():
    for p in (os.environ.get('GATE_SYSTEM_PYTHON', ''), __import__('sys').executable, __import__('sys').executable):
        if p and os.path.exists(p):
            return p
    return sys.executable

def main():
    py = system_python()
    try:
        p = subprocess.run([py, os.path.join(ROOT, 'checks', 'xss_room_ui.py')], cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300)
    except Exception as e:
        gc.emit('xss_browser', 'application', 'BLOCKED', [], blocked_reason='浏览器检查执行失败: ' + str(e)[:150])
        return
    if not os.path.exists(RESULT):
        gc.emit('xss_browser', 'application', 'BLOCKED', [], blocked_reason='未生成 xss_room_ui.json（可能缺少浏览器/登录）: ' + (p.stderr or '')[-150:])
        return
    try:
        r = json.load(open(RESULT, encoding='utf-8'))
    except Exception as e:
        gc.emit('xss_browser', 'application', 'BLOCKED', [], blocked_reason='结果解析失败: ' + str(e)[:120])
        return
    checks = r.get('checks') or {}
    verdict = checks.get('verdict')
    findings = []
    if verdict == 'POSSIBLE_XSS' or checks.get('window_xss'):
        findings.append(gc.finding('XSS-BROWSER', 'high', '管理后台 UI 渲染出现未转义 XSS payload', evidence=json.dumps(checks, ensure_ascii=False)[:400], remediation='输出编码/转义；CSP'))
        gc.emit('xss_browser', 'application', 'FAIL', findings, summary=json.dumps(checks, ensure_ascii=False)[:500])
        return
    if verdict == 'ESCAPED':
        gc.emit('xss_browser', 'application', 'PASS', [gc.finding('XSS-BROWSER-ESCAPED', 'info', 'UI 渲染为转义（不可利用）', evidence=json.dumps(checks, ensure_ascii=False)[:300])], summary='escaped')
        return
    gc.emit('xss_browser', 'application', 'BLOCKED', [], blocked_reason=f"UI 检查未得结论: {verdict}; create_code={r.get('create_code')}")
if __name__ == '__main__':
    main()
