"""内部版安全测试报告（AppScan 风格 + 可复现证据/标准化/修复闭环/附录）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
import time
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor, Inches
ROOT = 'configured-path'
GATE = os.path.join(ROOT, 'reports', 'final', 'gate')

def _server_version():
    v = os.environ.get('REPORT_VERSION', '')
    if v:
        return v
    try:
        return open(os.path.join(GATE, 'server_version.txt'), encoding='utf-8').read().strip() or 'unknown'
    except Exception:
        return 'unknown'
REPORT_VERSION = _server_version()
REPORT_NAME = f'私有云安全漏洞测试报告-V{REPORT_VERSION}'
OUT = os.path.join(ROOT, 'reports', 'final', REPORT_NAME + '.docx')
TARGET = _pub.target()
SEV_CN = {'critical': '严重', 'high': '高', 'medium': '中', 'low': '低', 'info': '信息'}
SEV_LABEL = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危', 'info': '信息'}
CAT_CN = {'application': '应用安全', 'crypto': '加密安全', 'component': '组件安全', 'middleware': '中间件安全', 'appscan': 'AppScan 外部报告'}
SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
SLA = {'critical': 3, 'high': 7, 'medium': 30, 'low': 90}
OWNER = {'application': '研发-应用', 'crypto': '研发-加密', 'component': '研发-组件', 'middleware': '运维-中间件', 'appscan': '研发-应用'}
APPSCAN_NAMES = {'HSTS': 'HSTS 响应头缺失', 'CORSArbitraryOrigin': 'CORS 允许任意 Origin', 'attNoContentTypeOptionsHeaderExist': 'X-Content-Type-Options 响应头缺失', 'attReferrerPolicyHeaderExist': 'Referrer-Policy 响应头缺失', 'attContentSecurityPolicyHeaderExist': 'Content-Security-Policy 响应头缺失', 'attXFrameOptionsHeaderExist': 'X-Frame-Options 响应头缺失', 'attCachedSSL': 'SSL 页面被缓存', 'attDirectoryDiscover': '目录发现', 'attDirectoryListing': '目录列表', 'attCookieJavaScript': 'Cookie 可被 JS 读取', 'attIPAddress': '内部 IP 地址泄露', 'attInternalIP': '内部 IP 地址泄露'}

def cn(s):
    return SEV_CN.get(str(s).lower(), str(s))

def heading(doc, text, level=1):
    p = doc.add_heading(text, level=level)
    for r in p.runs:
        r.font.name = '微软雅黑'
        r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    return p

def para(doc, text, bold=False, size=10):
    p = doc.add_paragraph()
    r = p.add_run(str(text))
    r.bold = bold
    r.font.size = Pt(size)
    r.font.name = '微软雅黑'
    r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    return p

def table(doc, headers, rows, font=8):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = 'Light Grid Accent 1'
    for (i, h) in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = str(h)
        for p in c.paragraphs:
            for r in p.runs:
                r.bold = True
                r.font.size = Pt(font)
                r.font.name = '微软雅黑'
                r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    for row in rows:
        cells = t.add_row().cells
        for (i, v) in enumerate(row):
            cells[i].text = str(v)
            for p in cells[i].paragraphs:
                for r in p.runs:
                    r.font.size = Pt(font - 1)
                    r.font.name = '微软雅黑'
                    r._element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    return t

def load_json(path, default=None):
    try:
        return json.load(open(path, encoding='utf-8'))
    except Exception:
        return default if default is not None else {}

def trivy_maps():
    p = os.path.join(GATE, 'trivy_product.json')
    data = load_json(p if os.path.exists(p) else os.path.join(GATE, 'trivy_sbom.json'))
    by = {}
    for r in data.get('Results') or []:
        for v in r.get('Vulnerabilities') or []:
            key = (v.get('VulnerabilityID'), v.get('PkgName'), v.get('InstalledVersion'))
            cv = v.get('CVSS') or {}
            score = 0.0
            vector = ''
            for src in ('nvd', 'redhat', 'ghsa'):
                if isinstance(cv.get(src), dict) and cv[src].get('V3Score'):
                    score = float(cv[src]['V3Score'])
                    vector = cv[src].get('V3Vector', '')
                    break
            by[key] = {'cvss': score, 'vector': vector, 'cwe': ','.join(v.get('CweIDs') or []), 'fixed': v.get('FixedVersion', ''), 'severity': str(v.get('Severity', '')).lower()}
    return by

def standard(item, trivy):
    text = (str(item.get('title', '')) + ' ' + str(item.get('id', ''))).lower()
    cat = item.get('category', '')
    if cat == 'component':
        m = re.search('Trivy:\\s*([^ ]+)\\s+([^ ]+)\\s+命中\\s+(\\S+)', str(item.get('title', '')))
        if m:
            t = trivy.get((m.group(3), m.group(1), m.group(2))) or {}
            if t.get('cvss'):
                return (round(t['cvss'], 1), t.get('cwe') or 'CWE-1104', 'A06:2021 易受攻击组件')
        return (7.5, 'CWE-1104', 'A06:2021 易受攻击组件')
    if 'xss' in text:
        return (6.1, 'CWE-79', 'A03:2021 注入')
    if 'sql' in text:
        return (9.8, 'CWE-89', 'A03:2021 注入')
    if 'rce' in text or 'snakeyaml' in text or '反序列' in text:
        return (9.8, 'CWE-502', 'A06:2021 易受攻击组件')
    if 'idor' in text or '越权' in text:
        return (7.5, 'CWE-639', 'A01:2021 访问控制失效')
    if 'md5' in text:
        return (7.5, 'CWE-916', 'A02:2021 加密机制失效')
    if '硬编码' in text or 'hardcoded' in text or '密钥' in text:
        return (7.5, 'CWE-321', 'A02:2021 加密机制失效')
    if '明文' in text or '密码' in text or 'secret' in text or ('weak' in text):
        return (8.8, 'CWE-521', 'A07:2021 身份鉴别失效')
    if 'header' in text or '响应头' in text:
        return (3.7, 'CWE-693', 'A05:2021 安全配置错误')
    if 'cookie' in text:
        return (5.4, 'CWE-614', 'A05:2021 安全配置错误')
    if '泄露' in text or 'exposure' in text or 'info' in text:
        return (5.3, 'CWE-200', 'A01:2021 访问控制失效')
    if '登录' in text or 'login' in text:
        return (7.5, 'CWE-307', 'A07:2021 身份鉴别失效')
    return (5.3, 'CWE-693', 'A05:2021 安全配置错误')

def evidence_examples(check, limit=2):
    p = os.path.join(GATE, 'evidence', check + '.json')
    if not os.path.exists(p):
        return ([], [])
    j = load_json(p)
    s = j.get('summary') or ''
    try:
        data = json.loads(s) if isinstance(s, str) else s
    except Exception:
        data = {}
    probes = []
    for key in ('details', 'probes', 'checks', 'observations'):
        val = data.get(key)
        if not isinstance(val, list):
            continue
        for x in val[:limit]:
            if isinstance(x, dict):
                probes.append(x)
    shots = []
    ed = j.get('evidence_dir') or ''
    if ed:
        for (root, _, files) in os.walk(ed):
            for f in files:
                if f.lower().endswith(('.png', '.jpg', '.jpeg')):
                    shots.append(os.path.join(root, f))
    return (probes[:limit], shots[:2])

def risk_type(it):
    check = str(it.get('check') or '')
    if check == 'weak_password_accounts':
        return '弱口令'
    if check in ('asset_inventory', 'login_discover'):
        return '登录入口'
    if it.get('category') == 'component' or check in ('tls_ssl_deep', 'crypto_inventory', 'client_crypto', 'crypto_app'):
        return '系统漏洞'
    return 'Web漏洞'

def asset_inventory():
    p = os.path.join(GATE, 'evidence', 'asset_inventory.json')
    j = load_json(p)
    try:
        return json.loads(j.get('summary') or '{}') if j else {}
    except Exception:
        return {}

def vuln_path(it):
    (probes, _) = evidence_examples(it.get('check', ''))
    if probes:
        p = probes[0]
        return f"{p.get('method', 'GET')} {TARGET}{p.get('path', '')}"
    if it.get('category') == 'component':
        m = re.search('Trivy:\\s*([^ ]+)\\s+([^ ]+)\\s+命中\\s+(\\S+)', str(it.get('title', '')))
        if m:
            return f'组件依赖：{m.group(1)} {m.group(2)}（{m.group(3)}）'
        m = re.search('依赖：\\s*([^\\s]+)\\s+([^\\s（]+)', str(it.get('title', '')))
        if m:
            return f'组件依赖：{m.group(1)} {m.group(2)}'
    if it.get('category') == 'crypto':
        m = re.search('"file"\\s*:\\s*"([^"]+)"', str(it.get('evidence', '')))
        if m:
            return f'文件：{m.group(1)}'
        return '数据存储/前端资源（见证据）'
    if it.get('category') == 'appscan':
        return f"AppScan 规则：{it.get('id')} / {TARGET}"
    return TARGET
USAGE = {'logback': 'Java 日志框架', 'jackson-core': 'JSON 序列化/解析', 'jackson-databind': 'JSON 反序列化/绑定', 'guava': 'Java 基础工具库', 'amqp-client': 'RabbitMQ Java 客户端', 'commons-beanutils': 'Java Bean 属性工具', 'commons-fileupload': '文件上传解析', 'commons-io': 'IO 工具库', 'commons-compress': '压缩/解压库', 'snakeyaml': 'YAML 解析'}

def comp_meta(name, sbom):
    low = str(name).lower()
    usage = next((v for (k, v) in USAGE.items() if k in low), '第三方 Java 库')
    artifact = str(name).split(':')[-1].lower()
    product = '产品（未定位）'
    for c in sbom.get('components') or []:
        cn = str(c.get('name') or '').lower()
        if artifact not in cn:
            continue
        path = str(c.get('path') or c.get('location') or '')
        if 'IceDBProxy' in path or 'icedbproxy' in path:
            return (usage, 'IceDBProxy')
        if 'fsp-boss' in path or 'fsp-base' in path or '/hst/paas/fsp-boss' in path:
            return (usage, 'fsp-boss')
    return (usage, product)

def fixed_for(it, trivy):
    if it.get('category') != 'component':
        return '—'
    m = re.search('Trivy:\\s*([^ ]+)\\s+([^ ]+)\\s+命中\\s+(\\S+)', str(it.get('title', '')))
    if not m:
        return '见组件表'
    t = trivy.get((m.group(3), m.group(1), m.group(2))) or {}
    return t.get('fixed') or '见组件表'

def http_records(check):
    d = os.path.join(GATE, 'evidence', 'http', check)
    recs = []
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            if f.endswith('.json'):
                r = load_json(os.path.join(d, f))
                if r:
                    recs.append(r)
    return recs

def screenshots_for(check):
    d = os.path.join(GATE, 'evidence', 'screenshots', check)
    if not os.path.isdir(d):
        return []
    return [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.lower().endswith(('.png', '.jpg', '.jpeg'))]

def format_http(recs, hint=''):
    if not recs:
        return '无 HTTP 原始报文（组件/文件类检查或未记录）'
    chosen = []
    if hint:
        for r in recs:
            u = str((r.get('request') or {}).get('url', ''))
            if hint and hint.split('?')[0] in u:
                chosen.append(r)
    chosen = (chosen or recs)[:2]
    lines = []
    for (i, r) in enumerate(chosen, 1):
        req = r.get('request') or {}
        resp = r.get('response') or {}
        body = req.get('body')
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False)[:800]
        lines.append(f"[请求 {i}] {req.get('method')} {req.get('url')}")
        if req.get('headers'):
            lines.append('请求Headers: ' + json.dumps(req['headers'], ensure_ascii=False)[:600])
        if req.get('params'):
            lines.append(f"参数: {json.dumps(req['params'], ensure_ascii=False)[:400]}")
        if body:
            lines.append(f'Body: {str(body)[:800]}')
        lines.append(f"[响应 {i}] HTTP {resp.get('status')}")
        if resp.get('headers'):
            lines.append('响应Headers: ' + json.dumps(resp['headers'], ensure_ascii=False)[:600])
        lines.append(f"响应Body: {str(resp.get('body', ''))[:1200]}")
    return '\n'.join(lines)

def probe_text(probes):
    if not probes:
        return ('未采集到请求细节（见检查证据文件）', '未采集到响应细节')
    (reqs, resps) = ([], [])
    for p in probes:
        path = p.get('path') or p.get('url') or ''
        method = p.get('method') or ('POST' if p.get('code') is not None else 'GET')
        if path:
            reqs.append(f'{method} {TARGET}{path}')
        payload = p.get('payload') or p.get('filename') or p.get('param')
        if payload:
            reqs.append(f'  payload/参数: {str(payload)[:120]}')
        code = p.get('code') or p.get('http') or p.get('admin')
        resps.append(f"HTTP {p.get('http', '')} / code {code}" if code is not None else '响应摘要见证据')
    return ('\n'.join(reqs) or '见证据文件', '；'.join(resps) or '见证据文件')

def impact_for(it):
    check = str(it.get('check') or '')
    title = str(it.get('title') or '')
    sev = str(it.get('severity') or '').lower()
    if it.get('category') == 'component':
        return '组件漏洞被实际加载/调用时，可能导致反序列化、远程代码执行、拒绝服务或敏感数据泄露；若该组件仅作为未加载的传递依赖，实际可利用性需研发确认。'
    if check in ('crypto_inventory', 'client_crypto', 'crypto_app', 'tls_ssl_deep', 'plaintext_http'):
        return '可能导致账号口令/会话被破解、敏感数据在传输或存储中被窃取、中间人攻击或不符合等保/密码合规要求。'
    if check == 'security_headers':
        return '浏览器缺少安全策略，可能增加 XSS、点击劫持、MIME 嗅探、敏感 Referer 泄露等攻击面；单项多为低危，但会影响整体 Web 安全基线。'
    if check == 'weak_password_accounts':
        return '攻击者可利用弱口令直接登录后台或业务系统，获取账号权限并进一步横向移动。'
    if check == 'login_rate_limit':
        return '攻击者可对登录接口进行低速暴力破解/撞库，增加账号被接管风险。'
    if check in ('endpoint_exposure', 'asset_inventory'):
        return '管理/调试接口或敏感文件暴露，可能泄露配置、接口文档、内部地址或业务数据。'
    if check in ('idor_matrix', 'idor_h5', 'idor_full', 'idor_objects', 'idor_recording_meeting'):
        return '攻击者可通过修改对象 ID 访问其他用户/部门的数据，造成越权读取、篡改或删除。'
    if check == 'xss_write_forms' or 'XSS' in title.upper():
        return '攻击者可注入脚本，在受害者浏览器中窃取会话、执行操作或钓鱼；存储型 XSS 影响面更大。'
    if 'SQL' in title.upper() or check.startswith('injection'):
        return '攻击者可通过注入读取/篡改数据库、绕过认证，严重时获取服务器权限。'
    if check == 'ssrf_check':
        return '服务端可能被诱导访问内网/云元数据/管理接口，造成内网探测、数据泄露或横向移动。'
    if check in ('upload_webshell', 'upload_content', 'upload_matrix', 'upload_xxe'):
        return '攻击者可能上传 webshell、触发 XXE 或通过文件解析漏洞执行代码/读取文件。'
    if check == 'file_download':
        return '攻击者可读取任意文件/源码/配置，导致敏感信息泄露，严重时辅助进一步利用。'
    if check in ('rce_probe', 'rce_write_chain', 'rce_deserialization', 'dependency_rce'):
        return '攻击者可能远程执行命令或反序列化利用，直接控制服务器。'
    if check == 'csrf_check' or check == 'csrf_ui_check':
        return '攻击者可诱导已登录用户执行非预期操作，造成数据修改或账号操作。'
    if check == 'open_redirect':
        return '可被用于钓鱼/绕过跳转白名单，降低用户对链接的信任边界。'
    if check == 'ip_spoof':
        return '日志/风控可能记录伪造来源 IP，影响审计追溯或绕过来源限制。'
    if check == 'nginx_bypass':
        return '可能绕过前置访问控制，访问本应 403 的接口、文件或管理路径。'
    if sev in ('critical', 'high'):
        return '可能导致服务器被控制、敏感数据泄露或业务中断，需优先处置。'
    if sev == 'medium':
        return '可能导致账号/数据/业务逻辑被滥用，需排期修复。'
    return '可能降低安全基线，建议结合业务影响评估后修复。'

def remediation_for(it, trivy):
    check = str(it.get('check') or '')
    title = str(it.get('title') or '')
    low = (check + ' ' + title).lower()
    if it.get('category') == 'component':
        fixed = fixed_for(it, trivy)
        if fixed in ('—', '见组件表'):
            fixed = '无公开修复版本时，升级/移除组件，或加白名单/WAF 补偿'
        return '1) 研发确认该组件是否被实际加载/调用及调用链；2) 升级到修复版本：%s；3) 重新构建并更新 SBOM；4) 用 Trivy/Grype 重扫确认 CVE 消失；5) 无法升级时移除依赖或增加运行时防护（WAF/RASP/白名单）并做风险接受。' % fixed
    if check in ('dependency_rce', 'rce_deserialization', 'rce_probe', 'rce_write_chain') or '反序列化' in title:
        return '1) 定位依赖及版本（如 snakeyaml/fastjson/log4j/jackson），确认调用链；2) 升级到无漏洞版本（snakeyaml>=2.0、fastjson>=1.2.83、log4j>=2.17.1 等，按 CVE 修复版本）；3) 禁止不可信数据进入反序列化；4) 开启 RASP/WAF 检测；5) 用原 POC 复测不可执行，并回归依赖相关业务。'
    if it.get('category') == 'appscan':
        t = title.lower()
        if 'header' in t or '响应头' in title:
            return '1) 在 nginx/网关补齐缺失响应头；2) 建议 HSTS、CSP、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy；3) 回归页面功能；4) curl -I 复测。'
        if 'cors' in t or '跨域' in title:
            return '1) 不要使用 Access-Control-Allow-Origin: * 搭配凭证；2) 使用域名白名单并校验 Origin；3) 限制 Allow-Methods/Allow-Headers；4) 复测非白名单 Origin 不返回 ACAO。'
        if 'ssl' in t or 'tls' in t or '证书' in title:
            return '1) 禁用 TLS1.0/1.1、3DES、RSA 密钥交换；2) 更新/续期证书；3) 启用 HSTS；4) 用 openssl/sslyze 复测。'
        if 'cookie' in t or 'cookie' in title.lower():
            return '1) 会话 Cookie 设置 HttpOnly、Secure、SameSite；2) 不在 JS 中写入会话；3) 复测 document.cookie 不可读。'
        if 'spring' in t or 'actuator' in t or 'swagger' in t or ('目录' in title):
            return '1) 生产关闭 Swagger/Actuator/目录浏览；2) 网关增加鉴权/IP 白名单；3) 清理备份/源码；4) 复测 401/403/404。'
        if 'ip' in t or '地址' in title or '路径' in title:
            return '1) 移除响应中的内部 IP/路径/版本信息；2) 自定义错误页；3) 清理调试头；4) 复测响应不再泄露内部信息。'
        return '1) 按 AppScan 规则定位具体 URL/参数；2) 在网关/应用层修复；3) 处理误报需记录证据；4) 用同一 URL 复测并更新 AppScan 对比。'
    if 'md5' in low or '密码哈希' in title or 'password' in low:
        return '1) 停止使用无盐 MD5；2) 迁移到 bcrypt/Argon2id/PBKDF2 加盐哈希；3) 登录成功后按新算法重算并平滑迁移；4) 强制高风险账号改密；5) 数据库字段/长度/索引同步调整；6) 回归登录、改密、找回流程。'
    if '3des' in low or '硬编码' in title or '密钥' in title or ('key' in low):
        return '1) 从前端 JS/配置/镜像中移除硬编码密钥；2) 立即轮换已暴露密钥；3) 改由服务端 KMS/密钥管理或短期令牌下发；4) 前端只做非敏感展示，不在客户端做可逆加密；5) 重新打包并扫描 JS/配置确认无残留；6) 评估历史数据是否需要重加密。'
    if 'tls' in low or '证书' in title or 'plaintext' in low or ('明文' in title):
        return '1) 禁用 TLS1.0/1.1、3DES、RSA 密钥交换；2) 仅启用 TLS1.2/1.3 + ECDHE/AEAD；3) 更新/续期证书并校验证书链和主机名；4) HTTP 强制 301 到 HTTPS 并启用 HSTS；5) 用 sslyze/openssl 复测协议、套件、证书。'
    if check == 'security_headers':
        return '1) 在 nginx/网关统一增加缺失响应头；2) 建议值：HSTS、CSP、X-Content-Type-Options=nosniff、X-Frame-Options=DENY/SAMEORIGIN、Referrer-Policy=strict-origin-when-cross-origin、Permissions-Policy；3) 对静态/API 分别配置 CSP；4) 回归页面功能，避免 CSP 误拦截；5) 用 curl -I 或 security_headers 检查复测。'
    if check == 'weak_password_accounts':
        return '1) 立即修改测试/默认账号口令；2) 禁止默认口令和弱口令字典；3) 启用强密码策略和 MFA；4) 对历史账号做弱口令排查；5) 复测弱口令账号不可登录，并保留整改记录。'
    if check == 'login_rate_limit':
        return '1) 增加登录失败计数、账号/IP 限速和锁定；2) 连续失败触发验证码/二次验证；3) 记录并告警暴力破解；4) 白名单/解锁流程；5) 用测试账号低速率复测锁定/限速生效。'
    if check in ('endpoint_exposure', 'asset_inventory'):
        return '1) 下线或限制 Swagger/Actuator/管理控制台/敏感文件；2) 网关/nginx 增加鉴权或 IP 白名单；3) 生产环境关闭 debug/actuator 全量端点；4) 清理备份/源码/配置暴露；5) 复测返回 401/403/404。'
    if check in ('idor_matrix', 'idor_h5', 'idor_full', 'idor_objects', 'idor_recording_meeting'):
        return '1) 所有对象接口增加“当前用户/部门是否有权访问该对象”校验；2) 不要只依赖前端隐藏或 ID 不可猜；3) 查询条件强制带 tenant/depart/owner 范围；4) 对读/改/删/导出统一鉴权；5) 用 A/B 双身份复测：B 访问 A 对象应返回 403/空数据。'
    if check == 'xss_write_forms' or 'xss' in low:
        return '1) 对输出做上下文编码（HTML/JS/URL/属性）；2) 富文本使用白名单过滤；3) 增加 CSP；4) 对输入做长度/字符/类型校验；5) 用同一 payload 在列表/详情/编辑页复测不执行。'
    if 'sql' in low or check.startswith('injection'):
        return '1) 使用参数化查询/预编译，禁止拼接 SQL；2) 对参数做类型/长度/白名单校验；3) 数据库账号最小权限；4) WAF 作为补偿但不替代修复；5) 用原 payload 复测无报错/差异。'
    if check == 'ssrf_check':
        return '1) URL 参数使用域名/协议/端口白名单；2) 禁止访问内网/回环/云元数据；3) 禁止跟随重定向；4) 出网统一代理并记录；5) 用 OAST/内网地址复测无回连。'
    if check in ('upload_webshell', 'upload_content', 'upload_matrix', 'upload_xxe'):
        return '1) 扩展名/内容类型/文件头白名单；2) 重命名为随机名并存储在非 Web 可执行目录；3) 服务端 AV/YARA 扫描；4) XML 解析禁用外部实体；5) 复测危险文件被拒绝/不可执行。'
    if check == 'file_download':
        return '1) 下载路径使用文件 ID 映射，不直接拼接用户路径；2) realpath 校验必须位于允许根目录；3) 禁止 ../、绝对路径、编码绕过；4) 鉴权到对象级；5) 复测任意路径返回 403/404。'
    if check in ('rce_probe', 'rce_write_chain', 'rce_deserialization', 'dependency_rce'):
        return '1) 升级受影响组件/框架；2) 禁用危险反序列化/命令执行入口；3) 输入白名单与最小权限；4) 增加 RASP/WAF 检测；5) 用原 POC 复测不可执行，并检查日志告警。'
    if check in ('csrf_check', 'csrf_ui_check'):
        return '1) 状态变更接口校验 CSRF Token/Origin/Referer；2) Cookie 设置 SameSite=Lax/Strict；3) 关键操作二次确认；4) 复测跨站请求被拒绝。'
    if check == 'open_redirect':
        return '1) 跳转目标使用白名单/相对路径；2) 拒绝外部 URL/协议；3) 复测恶意 next/redirect 参数不跳转外站。'
    if check == 'ip_spoof':
        return '1) 只信任可信代理链的 IP 头；2) 网关重写 X-Forwarded-For；3) 日志记录真实来源；4) 复测伪造头不影响审计/风控。'
    if check == 'nginx_bypass':
        return '1) 统一在后端做鉴权，不只靠 nginx location；2) 规范化路径并拒绝编码 NULL/..;/；3) 禁用 X-Original-URL/X-Rewrite-URL 覆盖；4) 复测 403 绕过变体仍被拒绝。'
    base = it.get('remediation') or '按检查项建议修复'
    return '1) 定位受影响接口/版本；2) %s；3) 增加回归用例；4) 复测确认风险消除。' % base

def steps_for(it):
    check = str(it.get('check') or '')
    path = vuln_path(it)
    if it.get('category') == 'component':
        return '1) 在 SBOM/部署包中定位组件及版本；2) 确认运行时是否加载；3) 对照 CVE/修复版本升级；4) 重扫 SBOM 并回归相关功能。'
    if check in ('dependency_rce', 'rce_deserialization', 'rce_probe', 'rce_write_chain'):
        return '1) 从 SBOM/模板/依赖树定位组件版本；2) 找到实际调用点/接口；3) 用无害 POC 在测试环境验证；4) 升级组件后重放 POC 确认不可执行；5) 回归业务流程。'
    if it.get('category') == 'appscan':
        return '1) 按 AppScan 规则找到对应 URL/请求；2) 在测试环境访问该 URL；3) 记录响应头/响应体/证书/CORS 等证据；4) 与修复后结果对比。'
    if check in ('weak_password_accounts', 'login_rate_limit'):
        return '1) 使用授权的测试账号；2) 按报告中的登录入口发起低速率请求；3) 观察失败提示/锁定/验证码；4) 不使用真实用户账号爆破。'
    if check in ('endpoint_exposure', 'file_download', 'upload_webshell', 'upload_content', 'upload_matrix', 'upload_xxe'):
        return '1) 访问报告中的路径/上传接口；2) 使用无害测试文件/标记内容；3) 观察状态码/响应内容；4) 完成后清理测试文件。'
    return '1) 使用报告中的入口：%s；2) 按证据中的请求/参数复现；3) 对比正常与异常响应；4) 保存请求/响应截图作为复测证据。' % path

def verify_for(it, trivy):
    check = str(it.get('check') or '')
    if it.get('category') == 'component':
        return '修复后：1) 重新生成 SBOM；2) 运行 trivy sbom / grype；3) 运行 checks/cve_gate.py、grype_cve.py、trivy_cve.py；4) 确认该 CVE 不再命中；5) 回归相关业务功能。'
    if check == 'security_headers':
        return '修复后：curl -I 或 security_headers 检查缺失头已存在，且不影响页面加载。'
    if check in ('weak_password_accounts', 'login_rate_limit'):
        return '修复后：用同一测试账号复测弱口令不可登录、连续失败触发限速/锁定。'
    if check in ('idor_matrix', 'idor_h5', 'idor_full', 'idor_objects', 'idor_recording_meeting'):
        return '修复后：用 test_user_a/test05 双身份复测，B 访问 A 对象应返回 403/空数据，并检查审计日志。'
    if check == 'xss_write_forms' or 'xss' in check:
        return '修复后：用同一 payload 在列表/详情/编辑页复测不执行，HTML 已编码。'
    if it.get('category') == 'appscan':
        return '修复后：用同一 URL/请求复测，并重跑 import_appscan 与 GATE_EXTERNAL_COMPARE，确认规则不再命中。'
    return '修复后重跑检查项 %s，并执行 runner/scan_before_release.ps1；报告中该条状态应为 PASS/无 finding。' % check

def main():
    g = load_json(os.path.join(GATE, 'gate_result.json'))
    trivy = trivy_maps()
    appscan = load_json(os.path.join(GATE, 'appscan_findings.json')).get('findings') or []
    sbom = load_json(os.path.join(GATE, 'sbom_merged.json'))
    grype = load_json(os.path.join(GATE, 'grype_sbom.json'))
    tp = os.path.join(GATE, 'trivy_product.json')
    trivy_raw = load_json(tp if os.path.exists(tp) else os.path.join(GATE, 'trivy_sbom.json'))
    gp = os.path.join(GATE, 'grype_product.json')
    grype = load_json(gp if os.path.exists(gp) else os.path.join(GATE, 'grype_sbom.json'))
    sp = os.path.join(GATE, 'sbom_product.json')
    sbom = load_json(sp if os.path.exists(sp) else os.path.join(GATE, 'sbom_merged.json'))
    items = []
    for (cat, c) in g['categories'].items():
        for f in c.get('findings') or []:
            if f.get('supplemental'):
                continue
            if str(f.get('id', '')).startswith('EXT-APPSCAN-'):
                continue
            items.append({'category': cat, 'id': f.get('id'), 'title': f.get('title'), 'severity': str(f.get('severity', '')).lower(), 'check': f.get('check'), 'evidence': f.get('evidence'), 'remediation': f.get('remediation')})
    for f in appscan:
        items.append({'category': 'appscan', 'id': 'EXT-' + str(f.get('rule')), 'title': APPSCAN_NAMES.get(str(f.get('rule')), str(f.get('title'))), 'severity': str(f.get('severity', '')).lower(), 'check': 'import_appscan', 'evidence': f.get('evidence'), 'remediation': '按 AppScan 规则修复'})
    for it in items:
        (cvss, cwe, owasp) = standard(it, trivy)
        (it['cvss'], it['cwe'], it['owasp']) = (cvss, cwe, owasp)
        it['owner'] = OWNER.get(it['category'], '研发')
        it['sla'] = SLA.get(it['severity'], 30)
        it['risk_type'] = risk_type(it)
    asset = asset_inventory()
    counts = {k: 0 for k in SEV_CN}
    for it in items:
        if it['severity'] in counts:
            counts[it['severity']] += 1
    doc = Document()
    sec = doc.sections[0]
    sec.top_margin = Pt(30)
    sec.bottom_margin = Pt(30)
    st = doc.styles['Normal']
    st.font.name = '微软雅黑'
    st.font.size = Pt(9)
    st.element.rPr.rFonts.set(qn('w:eastAsia'), '微软雅黑')
    for _ in range(4):
        doc.add_paragraph('')
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(REPORT_NAME)
    r.bold = True
    r.font.size = Pt(21)
    r.font.color.rgb = RGBColor(31, 58, 95)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run('发版前安全评估 · 完整证据与复现脚本')
    r.font.size = Pt(13)
    doc.add_paragraph('')
    table(doc, ['项目', '内容'], [['报告版本', f'V{REPORT_VERSION} / 内部版 / 2026-11-24'], ['测试对象', TARGET], ['主机范围', '' + _pub.shell('SEC_DB_HOST') + '（Kylin V10 应用/DB/中间件）、' + _pub.shell('SEC_DB_HOST') + '（扫描执行/工具）'], ['测试类型', '自动化门禁 + SBOM/CVE + AppScan 报告对比 + 人工复核'], ['总体结论', g.get('overall')], ['密级', '内部（含完整证据/脚本，请勿外发）']])
    doc.add_page_break()
    heading(doc, '1. 综述', 1)
    total = len(items)
    if counts['critical'] or counts['high']:
        overall_level = '高危'
    elif counts['medium']:
        overall_level = '中危'
    elif counts['low']:
        overall_level = '低危'
    else:
        overall_level = '安全'
    para(doc, f"本次针对云会议 Web 后台执行发版前安全评估，共执行 {len(g['checks'])} 项检查，发现 {total} 条漏洞/风险项。", bold=True)
    para(doc, f"总体安全等级：{overall_level}；严重 {counts['critical']}、高危 {counts['high']}、中危 {counts['medium']}、低危 {counts['low']}。")
    para(doc, f"门禁结论：{g.get('overall')}；按当前“报告模式”策略不阻断发版；高危项建议修复后再发版。")
    table(doc, ['风险等级', '风险值区间', '数量', '处置建议'], [['严重', '9–10', counts['critical'], '立即修复'], ['高危', '7–9', counts['high'], '发版前修复'], ['中危', '4–7', counts['medium'], '排期修复'], ['低危', '0–4', counts['low'], '观察/加固'], ['合计', '—', total, '—']])
    heading(doc, '1.1 按风险类型统计', 2)
    table(doc, ['风险类型', '严重', '高危', '中危', '低危', '合计'], [[rt, sum((1 for x in items if x['risk_type'] == rt and x['severity'] == 'critical')), sum((1 for x in items if x['risk_type'] == rt and x['severity'] == 'high')), sum((1 for x in items if x['risk_type'] == rt and x['severity'] == 'medium')), sum((1 for x in items if x['risk_type'] == rt and x['severity'] == 'low')), sum((1 for x in items if x['risk_type'] == rt))] for rt in ('系统漏洞', 'Web漏洞', '弱口令', '登录入口')])
    heading(doc, '1.2 门禁四类结果', 2)
    table(doc, ['类别', '状态', '阻断项'], [[CAT_CN.get(k, k), c['status'], len(c['blocking_findings'])] for (k, c) in g['categories'].items()])
    heading(doc, '2. 资产统计', 1)
    heading(doc, '2.1 资产基本信息', 2)
    table(doc, ['项', '值'], [['目标 URL', asset.get('target') or TARGET], ['主机资产', '、'.join(asset.get('hosts') or [_pub.env('SEC_SSH_HOST', ''), _pub.env('SEC_SSH_HOST', '')])], ['设备类型', '服务器设备 / Web 应用'], ['操作系统', 'Kylin V10（155）、openEuler（180）'], ['资产名称', '云视频会议系统 Web 后台'], ['责任人/业务组', '待补充'], ['测试时间', time.strftime('%Y-%m-%d %H:%M')], ['测试工具', '自研门禁 V8.2、Trivy、Grype、AppScan、Playwright']])
    heading(doc, '2.2 资产端口信息', 2)
    ports = asset.get('ports') or [28443, 22, 22002, 22003, 22007, 25672]
    table(doc, ['端口', '协议', '服务', '说明'], [[str(p), 'tcp', {28443: 'https', 22: 'ssh', 22007: 'mysql', 22002: 'redis', 22003: 'redis', 25672: 'rabbitmq'}.get(p, 'unknown'), '资产端口'] for p in ports])
    heading(doc, '2.3 Web/登录入口', 2)
    entries = asset.get('web_entries') or [{'name': '管理端登录', 'url': TARGET + '/ui/login', 'http': '-'}]
    table(doc, ['入口名称', 'URL', 'HTTP'], [[e.get('name'), e.get('url'), e.get('http')] for e in entries])
    heading(doc, '2.4 组件扫描范围（仅产品）', 2)
    para(doc, '经确认：fsp-boss、IceDBProxy，以及部署包自带的中间件 hst-icegridregistry、hst-zookeeper、hst-rabbitmq、hst-redis、hst-redis-sentinel、hst-mysql 均为我方产品，全部纳入产品范围；仅排除 OS 系统 RPM/DEB 与容器基础 OS 包（系统级）。')
    table(doc, ['范围', '说明'], [['产品组件（已确认）', 'fsp-boss、IceDBProxy、中间件 hst-*、paas/fsp-boss、deploy 下 Java 依赖'], ['产品中间件', 'hst-icegridregistry、hst-zookeeper、hst-rabbitmq、hst-redis、hst-redis-sentinel、hst-mysql'], ['排除：系统包', 'Kylin/openEuler OS RPM/DEB（系统级）'], ['排除：容器基础 OS', '容器基础镜像中的系统包（非产品 Java/中间件组件）'], ['产品 SBOM', 'sbom_product.json / sbom_product_cyclonedx.json'], ['产品组件数', '343（含中间件 Java 库）']])
    heading(doc, '3. 风险统计', 1)
    heading(doc, '3.1 风险等级统计', 2)
    table(doc, ['风险等级', '数量', '占比', '风险值区间'], [['严重', counts['critical'], f"{counts['critical'] / max(total, 1) * 100:.1f}%", '9–10'], ['高危', counts['high'], f"{counts['high'] / max(total, 1) * 100:.1f}%", '7–9'], ['中危', counts['medium'], f"{counts['medium'] / max(total, 1) * 100:.1f}%", '4–7'], ['低危', counts['low'], f"{counts['low'] / max(total, 1) * 100:.1f}%", '0–4'], ['合计', total, '100%', '—']])
    heading(doc, '3.2 按风险类型统计', 2)
    table(doc, ['风险类型', '数量', '资产等级说明'], [['系统漏洞', sum((1 for x in items if x['risk_type'] == '系统漏洞')), '组件/系统类风险'], ['Web漏洞', sum((1 for x in items if x['risk_type'] == 'Web漏洞')), 'Web 应用/API 风险'], ['弱口令', sum((1 for x in items if x['risk_type'] == '弱口令')), '账号口令风险'], ['登录入口', sum((1 for x in items if x['risk_type'] == '登录入口')), '入口暴露信息']])
    heading(doc, '3.3 组件 CVE 分组（含用途/所属产品）', 2)
    groups = {}
    for it in items:
        if it['category'] != 'component':
            continue
        m = re.search('Trivy:\\s*([^ ]+)\\s+([^ ]+)\\s+命中\\s+(\\S+)', str(it['title']))
        if m:
            k = f'{m.group(1)} {m.group(2)}'
            (usage, product) = comp_meta(m.group(1), sbom)
            groups.setdefault(k, {'cves': [], 'cvss': it['cvss'], 'fixed': '', 'sev': it['severity'], 'usage': usage, 'product': product})
            groups[k]['cves'].append(m.group(3))
            t2 = trivy.get((m.group(3), m.group(1), m.group(2))) or {}
            groups[k]['fixed'] = t2.get('fixed') or groups[k]['fixed']
    table(doc, ['组件', '用途', '所属产品', '最高严重性', 'CVSS', 'CVE 数', '修复版本', 'CVE'], [[k, v['usage'], v['product'], cn(v['sev']), v['cvss'], len(v['cves']), v['fixed'], ', '.join(sorted(set(v['cves'])))[:80]] for (k, v) in groups.items()], font=7)
    heading(doc, '4. 漏洞详情', 1)
    detailed = sorted(items, key=lambda x: (SEV_ORDER.get(x['severity'], 9), x['category']))
    for (i, it) in enumerate(detailed, 1):
        heading(doc, f"VUL-2026-0729-{i:03d} {it['title']}", 2)
        (probes, _) = evidence_examples(it['check'])
        shots = screenshots_for(it['check'])
        (req, resp) = probe_text(probes)
        hint = str((probes[0].get('path') if probes else '') or '')
        http_txt = format_http(http_records(it['check']), hint)
        detail = f"标准：CVSS {it['cvss']} / {it['cwe']} / {it['owasp']}\n检测项：{it['check']}\n证据：{str(it['evidence'])[:500]}\n复现：{req}\n响应摘要：{resp}\n完整请求/响应：\n{http_txt}\n截图/附件：{('；'.join(shots) if shots else '未采集（非浏览器检查；HTTP 原始报文见 reports/final/gate/evidence/http/' + str(it['check']) + '）')}"
        desc = f"{it['title']}（类别：{CAT_CN.get(it['category'], it['category'])}；CVSS {it['cvss']}；{it['cwe']}；{it['owasp']}）"
        if it['category'] == 'component':
            mm = re.search('Trivy:\\s*([^ ]+)', str(it['title']))
            if mm:
                (usage, product) = comp_meta(mm.group(1), sbom)
                desc += f'；用途：{usage}；所属产品：{product}'
        table(doc, ['字段', '内容'], [['漏洞路径', vuln_path(it)], ['风险等级', SEV_LABEL.get(it['severity'], it['severity'])], ['漏洞描述', desc], ['影响范围', impact_for(it)], ['详情', detail], ['复现步骤', steps_for(it)], ['修复建议', remediation_for(it, trivy) + (f'\n修复版本：{fixed_for(it, trivy)}' if fixed_for(it, trivy) not in ('—', '见组件表') else '')], ['修复情况', '未修复（本轮仅检测；按风险等级排期整改）'], ['复测详情', verify_for(it, trivy)], ['参考标准', f"CVSS {it['cvss']}；{it['cwe']}；{it['owasp']}"]])
        shots2 = screenshots_for(it['check'])
        if shots2:
            try:
                doc.add_picture(shots2[0], width=Inches(5.8))
                cap = doc.add_paragraph(f'截图：{os.path.basename(shots2[0])}')
                cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            except Exception:
                pass
    all_shots = []
    for c in g.get('checks') or {}:
        all_shots.extend(screenshots_for(c))
    if all_shots:
        heading(doc, '4.99 页面截图证据', 2)
        para(doc, f'共采集 {len(all_shots)} 张页面截图，作为 XSS/UI 检查的辅助证据。')
        for sp in all_shots[:12]:
            try:
                doc.add_picture(sp, width=Inches(5.8))
                cap = doc.add_paragraph(f'截图：{os.path.basename(sp)} ({os.path.dirname(sp)})')
                cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            except Exception:
                pass
    heading(doc, '4.99 风险接受与签字', 2)
    table(doc, ['角色', '签字', '日期', '备注'], [['产品负责人', '', '', ''], ['研发负责人', '', '', ''], ['安全负责人', '', '', '']])
    heading(doc, '5. 安全建议', 1)
    para(doc, '根据本次评估结果，建议按以下优先级开展整改：')
    for s in ['1. 优先修复高危/严重项：组件 CVE、硬编码密钥/默认口令、越权/未授权接口；', '2. 对 Web 注入、XSS、上传、下载、SSRF/CSRF 等建立上线前自动化回归；', '3. 统一认证失败提示、增加验证码/登录限速，定期排查弱口令；', '4. 收敛 Swagger/Actuator/中间件控制台等管理面，仅内网/鉴权访问；', '5. 建立漏洞库更新、复测与风险接受流程，修复后回归本报告检查项。']:
        para(doc, s)
    heading(doc, '6. 参考标准', 1)
    heading(doc, '6.1 单一系统漏洞风险等级评定标准', 2)
    table(doc, ['危险程度', '危险值区域', '危险程度说明'], [['严重', '9 <= 漏洞风险值 <= 10', '漏洞可能导致系统崩溃、数据泄露等严重后果，易受攻击，影响范围广，修复难度大，需要立即修复。'], ['高危', '7 <= 漏洞风险值 < 9', '漏洞可能导致系统受到攻击或数据被盗取，易受攻击，影响范围较广，修复难度较大，需要尽快修复。'], ['中危', '4 <= 漏洞风险值 < 7', '漏洞可能导致系统受到攻击或数据泄露，易受攻击，影响范围较小，修复难度一般，需要在合理的时间内修复。'], ['低危', '0 <= 漏洞风险值 < 4', '漏洞可能导致系统受到攻击或数据泄露的风险较小，不易受攻击，修复难度较小，可以在合理的时间内修复。']], font=8)
    heading(doc, '6.2 单一Web漏洞风险等级评定标准', 2)
    table(doc, ['危险程度', '危险值区域', '危险程度说明'], [['严重', '9 <= 漏洞风险值 <= 10', '漏洞可能导致系统崩溃、数据泄露等严重后果，易受攻击，影响范围广，修复难度大，需要立即修复。'], ['高危', '7 <= 漏洞风险值 < 9', '漏洞可能导致系统受到攻击或数据被盗取，易受攻击，影响范围较广，修复难度较大，需要尽快修复。'], ['中危', '4 <= 漏洞风险值 < 7', '漏洞可能导致系统受到攻击或数据泄露，易受攻击，影响范围较小，修复难度一般，需要在合理的时间内修复。'], ['低危', '0 <= 漏洞风险值 < 4', '漏洞可能导致系统受到攻击或数据泄露的风险较小，不易受攻击，修复难度较小，可以在合理的时间内修复。']], font=8)
    heading(doc, '6.3 单一资产风险等级评定标准', 2)
    table(doc, ['危险程度', '危险程度说明'], [['高危', '资产存在高危风险的漏洞，风险等级为高风险，建议优先关注。'], ['中危', '资产只发现中危及以下风险等级的漏洞，风险等级为中风险。'], ['低危', '资产只发现低危风险的漏洞，风险值等级较低。'], ['安全', '不存在高中低风险的漏洞，不存在脆弱性风险']], font=8)
    heading(doc, '附录 A 内部证据与原始数据', 1)
    heading(doc, 'A.1 AppScan 对比与覆盖', 2)
    ext = os.path.join(GATE, 'GATE_EXTERNAL_COMPARE.md')
    if os.path.exists(ext):
        for line in open(ext, encoding='utf-8'):
            if line.startswith('- ') or '覆盖' in line:
                para(doc, line.strip().lstrip('- '))
    heading(doc, 'A.2 误报评估与人工确认建议', 2)
    table(doc, ['类别', '典型发现', '判断', '建议'], [['已确认（高置信）', 'DB MD5、前端硬编码 3DES、响应头缺失、TLS 证书即将过期', '真阳性', '按建议修复'], ['需运行时确认', '25 个组件 CVE（logback/jackson/snakeyaml 等）', '可能含未实际加载的传递依赖', '研发确认运行时加载；未加载可走例外'], ['需人工确认', '明文密码/密钥、弱口令、登录限速', '测试账号/默认值可能造成误报', '确认测试数据；生产账号整改'], ['设计确认', 'idor_h5 普通用户可看公司通讯录', '可能是产品设计（通讯录）', '产品确认数据范围'], ['外部导入', 'AppScan 23 条规则', '未在本工具内独立复现', '同目标复测或 URL 级确认']], font=7)
    heading(doc, 'A.3 Trivy 原始结果（高危）', 2)
    rows = []
    for r in trivy_raw.get('Results') or []:
        for v in r.get('Vulnerabilities') or []:
            if str(v.get('Severity', '')).lower() in ('high', 'critical'):
                t2 = trivy.get((v.get('VulnerabilityID'), v.get('PkgName'), v.get('InstalledVersion'))) or {}
                rows.append([v.get('VulnerabilityID'), v.get('PkgName'), v.get('InstalledVersion'), v.get('Severity'), t2.get('cvss'), t2.get('cwe'), v.get('FixedVersion')])
    table(doc, ['CVE', '组件', '当前版本', '严重性', 'CVSS', 'CWE', '修复版本'], rows, font=7)
    heading(doc, 'A.4 Grype 原始结果（高危）', 2)
    rows = []
    for m in grype.get('matches') or []:
        v = m.get('vulnerability') or {}
        a = m.get('artifact') or {}
        if str(v.get('severity', '')).lower() in ('high', 'critical'):
            rows.append([v.get('id'), a.get('name'), a.get('version'), v.get('severity'), ','.join(v.get('fix', {}).get('versions') or [])])
    table(doc, ['GHSA/CVE', '组件', '版本', '严重性', '修复版本'], rows, font=7)
    heading(doc, 'A.5 AppScan 规则映射表', 2)
    mapping_rows = []
    if os.path.exists(ext):
        for line in open(ext, encoding='utf-8'):
            if line.startswith('|') and '---' not in line and ('外部规则' not in line):
                cells = [x.strip() for x in line.strip('|').split('|')]
                if len(cells) >= 4:
                    mapping_rows.append(cells[:4])
    table(doc, ['AppScan 规则', '严重性', '映射检查', '是否覆盖'], mapping_rows, font=7)
    dbp = os.path.join(GATE, 'vuln_db_status.json')
    if os.path.exists(dbp):
        db = load_json(dbp)
        tr = db.get('trivy') or {}
        heading(doc, 'A.6 漏洞库版本与新鲜度', 2)
        table(doc, ['漏洞库', '字段', '值'], [['Trivy DB', 'UpdatedAt', tr.get('UpdatedAt', '-')], ['Trivy DB', 'NextUpdate', tr.get('NextUpdate', '-')], ['Grype DB', 'Status', (db.get('grype') or {}).get('status_text', '-')[:800]]])
    heading(doc, 'A.7 原始数据与脚本', 2)
    for x in ['gate_result.json / CHECK_MATRIX.md / REMEDIATION.csv', 'trivy_sbom.json / grype_sbom.json / sbom_merged.json', 'appscan_findings.json / GATE_EXTERNAL_COMPARE.md', 'checks/ 下各检查脚本；runner/scan_before_release.ps1']:
        para(doc, '- ' + x)
    doc.save(OUT)
    print('docx:', OUT)
if __name__ == '__main__':
    main()
