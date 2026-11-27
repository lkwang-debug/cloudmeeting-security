"""HST 视频会议管理后台 —— 自动登录获取 Bearer Token

用途
----
管理后台的 token 有有效期（实测 57 字符、随登录会话下发）。当复测脚本
(hst_repro.py) 依赖的 token 过期时，用本工具重新登录拿新 token。

实现方式
--------
后台登录需要「点选式中文验证码」：先 GET /auth/v1/login/verifyCode 拿到
图片 + 目标汉字序列 + RSA 公钥，用户按序列点击图片中对应汉字，坐标经 RSA
加密后随 verifyId 提交，口令则用前端硬编码 keyen 做 AES 加密。

为避免重写前端加密逻辑，本工具用 Playwright 驱动真实 Chrome 完成登录
（浏览器自己处理 AES/RSA），只用 ddddocr 识别验证码汉字坐标，再在页面
上按序派发 click 事件。

依赖（仅本工具需要，复现脚本本身仍为纯标准库）
--------------------------------------------
    pip install playwright ddddocr pillow
    本机需已安装 Chrome（默认自动探测常见路径，可用 --chrome 指定）

用法
----
    # 口令从环境变量读（推荐，避免进 shell 历史）
    set HST_PWD=******
    python tools/admin_login.py --username sysmanager --password-env HST_PWD

    # 直传口令（会写入进程参数，仅测试环境使用）
    python tools/admin_login.py --username sysmanager --password ******

    # 指定目标/输出/Chrome 路径，最多 3 次验证码重试
    python tools/admin_login.py --target https://192.0.2.10:28443         --username sysmanager --password-env HST_PWD         --out evidence/admin_token.txt --attempts 3         --chrome "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"

输出
----
- token 写入 --out（默认 evidence/admin_token.txt），文件权限尽量收紧
- 控制台只打印脱敏 token（前 8 位 + 长度）
- 审计留痕：evidence/raw/LOGIN/login_captcha_a<N>.png、login_response.json（均脱敏）

退出码
------
0 成功；2 验证码识别失败（未产生登录请求）；3 参数/依赖错误；1 登录失败

安全说明
--------
- 仅用于已授权目标；登录会产生真实登录审计日志。
- 验证码识别失败时**不会提交登录**，避免无效尝试累积触发账号锁定。
- token 是敏感凭据，勿提交到版本库或外发。
"""
from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
from runner import public_config as _pub
import argparse
import base64
import io
import json
import os
import re
import sys
import time
TOOL_NAME = 'hst-admin-login'
TOOL_VERSION = '1.0'
DEFAULT_TARGET = _pub.target()
DEFAULT_OUT = os.path.join('evidence', 'admin_token.txt')
DEFAULT_ATTEMPTS = 3
CHROME_CANDIDATES = ['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe']
CAPTCHA_SELECTOR = 'img[src^="data:image"]'
TARGET_RE = re.compile('请依次点击[：:]\\s*([^\\n\\r]{1,30})')
HANZI_RE = re.compile('[^\\u4e00-\\u9fff]')

def mask(value: str, keep: int=8) -> str:
    if not value:
        return ''
    return '%s...(len=%d)' % (value[:keep], len(value))

def find_chrome(explicit: str='') -> str:
    if explicit:
        return explicit
    for path in CHROME_CANDIDATES:
        if os.path.isfile(path):
            return path
    return ''

def require_deps():
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        print('[!] 缺少 playwright：pip install playwright', file=sys.stderr)
        raise SystemExit(3)
    try:
        import ddddocr
        from PIL import Image
    except Exception:
        print('[!] 缺少 ddddocr / pillow：pip install ddddocr pillow', file=sys.stderr)
        raise SystemExit(3)

class CaptchaSolver(object):
    """det 找字框 + cls 识别单字，供点选验证码按序取坐标。"""

    def __init__(self):
        import ddddocr
        self._det = ddddocr.DdddOcr(det=True, show_ad=False)
        self._cls = ddddocr.DdddOcr(beta=True, show_ad=False)

    def solve(self, img_bytes: bytes):
        """返回 (boxes, size)。boxes: [{"ch","x","y","box"}]，坐标为原图像素。"""
        from PIL import Image
        image = Image.open(io.BytesIO(img_bytes))
        boxes = []
        for raw in self._det.detection(img_bytes):
            (x1, y1, x2, y2) = [int(v) for v in raw]
            if x2 - x1 < 14 or y2 - y1 < 14:
                continue
            crop = image.crop((x1, y1, x2, y2))
            buf = io.BytesIO()
            crop.save(buf, format='PNG')
            text = (self._cls.classification(buf.getvalue()) or '').strip()
            if not text:
                continue
            boxes.append({'ch': text, 'x': (x1 + x2) // 2, 'y': (y1 + y2) // 2, 'box': [x1, y1, x2, y2]})
        return (boxes, image.size)

def match_points(target: str, boxes):
    """按目标字序列在 boxes 里找坐标；找不到返回 None（调用方不得提交）。"""
    used = set()
    points = []
    for ch in target:
        hit = None
        for (idx, item) in enumerate(boxes):
            if idx in used:
                continue
            if item['ch'] == ch:
                hit = idx
                break
        if hit is None:
            for (idx, item) in enumerate(boxes):
                if idx in used:
                    continue
                if ch and (ch in item['ch'] or item['ch'] in ch):
                    hit = idx
                    break
        if hit is None:
            return None
        used.add(hit)
        points.append((boxes[hit]['x'], boxes[hit]['y']))
    return points

def click_points(page, points, natural_size):
    """在验证码图片元素上按序派发 click；坐标按原图 → 显示尺寸换算。"""
    rect = page.evaluate('(sel) => {\n            const els = document.querySelectorAll(sel);\n            let img = null, max = 0;\n            for (const e of els) { if (e.src.length > max) { max = e.src.length; img = e; } }\n            const r = img.getBoundingClientRect();\n            return {left: r.left, top: r.top, width: r.width, height: r.height,\n                    dw: img.naturalWidth || 320, dh: img.naturalHeight || 160};\n        }', CAPTCHA_SELECTOR)
    dw = rect['dw'] or natural_size[0]
    dh = rect['dh'] or natural_size[1]
    for (cx, cy) in points:
        client_x = rect['left'] + cx * rect['width'] / dw
        client_y = rect['top'] + cy * rect['height'] / dh
        page.evaluate("({sel, x, y}) => {\n                const els = document.querySelectorAll(sel);\n                let img = null, max = 0;\n                for (const e of els) { if (e.src.length > max) { max = e.src.length; img = e; } }\n                img.dispatchEvent(new MouseEvent('click', {bubbles: true, clientX: x, clientY: y}));\n            }", {'sel': CAPTCHA_SELECTOR, 'x': client_x, 'y': client_y})
        page.wait_for_timeout(400)
    return rect

def main(argv=None):
    parser = argparse.ArgumentParser(prog='admin_login.py', description='HST 管理后台自动登录并获取 Bearer Token（点选式中文验证码）')
    parser.add_argument('--target', default=DEFAULT_TARGET, help='后台地址')
    parser.add_argument('--username', default='sysmanager', help='后台账号')
    parser.add_argument('--password', default='', help='后台口令（不推荐，见 --password-env）')
    parser.add_argument('--password-env', default='', metavar='VAR', help='从该环境变量读取口令（推荐）')
    parser.add_argument('--out', default=DEFAULT_OUT, help='token 输出文件路径')
    parser.add_argument('--attempts', type=int, default=DEFAULT_ATTEMPTS, help='验证码最多重试次数（每次都会重新取图；识别失败不提交登录）')
    parser.add_argument('--chrome', default='', help='Chrome/Edge 可执行文件路径')
    parser.add_argument('--headless', action='store_true', default=True, help='无头模式（默认开）')
    parser.add_argument('--evidence-dir', default=os.path.join('evidence', 'raw', 'LOGIN'), help='验证码/响应审计留痕目录')
    parser.add_argument('--timeout', type=float, default=25.0, help='等待验证码超时秒数')
    args = parser.parse_args(argv)
    password = args.password
    if args.password_env:
        password = os.environ.get(args.password_env, '')
    if not password:
        print('[!] 未提供口令：用 --password-env VAR 或 --password', file=sys.stderr)
        return 3
    if args.attempts < 1 or args.attempts > 6:
        print('[!] --attempts 取值 1-6（避免无效尝试）', file=sys.stderr)
        return 3
    require_deps()
    from playwright.sync_api import sync_playwright
    chrome = find_chrome(args.chrome)
    if not chrome:
        print('[!] 未找到 Chrome/Edge，请用 --chrome 指定', file=sys.stderr)
        return 3
    url = args.target.rstrip('/') + '/#/ui/login'
    os.makedirs(args.evidence_dir, exist_ok=True)
    solver = CaptchaSolver()
    print('%s v%s | 目标: %s | 账号: %s' % (TOOL_NAME, TOOL_VERSION, args.target, args.username))
    captured = {}
    token = ''
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=args.headless, executable_path=chrome, args=['--ignore-certificate-errors', '--no-sandbox'])
        ctx = browser.new_context(ignore_https_errors=True, viewport={'width': 1500, 'height': 950})
        page = ctx.new_page()

        def on_response(resp):
            if '/auth/v1/login' in resp.url and resp.request.method == 'POST':
                try:
                    captured.update({'body': resp.text(), 'status': resp.status, 'headers': dict(resp.headers)})
                except Exception:
                    pass
        page.on('response', on_response)
        for attempt in range(1, args.attempts + 1):
            print('\n[第 %d/%d 次] 拉取验证码...' % (attempt, args.attempts))
            page.goto(url, wait_until='networkidle', timeout=60000)
            page.wait_for_timeout(1200)
            try:
                page.fill('input[placeholder*="用户名"]', args.username)
            except Exception:
                page.fill('input[type="text"]', args.username)
            page.fill('input[type="password"]', password)
            page.click('button:has-text("登")')
            page.wait_for_selector(CAPTCHA_SELECTOR, timeout=int(args.timeout * 1000))
            page.wait_for_timeout(700)
            imgs = page.locator(CAPTCHA_SELECTOR)
            best_src = ''
            for i in range(imgs.count()):
                src = imgs.nth(i).get_attribute('src') or ''
                if len(src) > len(best_src):
                    best_src = src
            img_bytes = base64.b64decode(best_src.split(',', 1)[1])
            png_path = os.path.join(args.evidence_dir, 'login_captcha_a%d.png' % attempt)
            with open(png_path, 'wb') as fh:
                fh.write(img_bytes)
            (boxes, size) = solver.solve(img_bytes)
            page_text = page.inner_text('body')
            m = TARGET_RE.search(page_text)
            target = HANZI_RE.sub('', m.group(1)) if m else ''
            print('  目标字: %s | OCR: %s' % (target or '(未取到)', [(b['ch'], b['x'], b['y']) for b in boxes]))
            points = match_points(target, boxes) if target else None
            if not points or len(points) != len(target):
                print('  OCR 与目标不匹配 → 换一张重试（未提交登录，避免锁号）')
                continue
            print('  点击坐标(原图): %s' % (points,))
            click_points(page, points, size)
            print('  已按序点击，等待登录结果...')
            page.wait_for_timeout(5000)
            if captured.get('body') or '/#/ui/login' not in page.url:
                break
        if captured.get('body'):
            raw = captured['body']
            try:
                payload = json.loads(raw)
                token = (payload.get('data') or {}).get('token') or ''
                print('\n登录响应: code=%s msg=%s' % (payload.get('code'), payload.get('msg')))
            except Exception:
                pass
            masked_body = re.sub('("(?:token|authorization)"\\s*:\\s*)"([^"]{8,})"', lambda mm: '%s"%s...(len=%d)"' % (mm.group(1), mm.group(2)[:8], len(mm.group(2))), raw)
            with open(os.path.join(args.evidence_dir, 'login_response.json'), 'w', encoding='utf-8') as fh:
                fh.write(masked_body)
        if not token:
            try:
                token = page.evaluate("() => { try {\n                        return localStorage.getItem('token')\n                            || (document.cookie.match(/token=([^;]+)/) || [])[1];\n                    } catch (e) { return null; } }") or ''
            except Exception:
                token = ''
        browser.close()
    if not token:
        print('[!] 登录失败：未取得 token（未产生或验证码未通过）', file=sys.stderr)
        return 1
    out_path = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(token.strip() + '\n')
    try:
        os.chmod(out_path, 384)
    except Exception:
        pass
    print('\n[+] 登录成功，token = %s' % mask(token.strip()))
    print('    已写入: %s' % out_path)
    return 0
if __name__ == '__main__':
    sys.exit(main())
