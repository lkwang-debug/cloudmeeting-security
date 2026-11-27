"""汇总客户报告中的漏洞类别与关键词。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import re
from collections import Counter
ROOT = 'configured-path'
SRC = os.path.join(ROOT, 'reports', 'final', 'customer_reports')
OUT_MD = os.path.join(SRC, '_SUMMARY.md')
OUT_JSON = os.path.join(SRC, '_SUMMARY.json')
CATS = {'弱口令/默认口令': '弱口令|默认口令|默认密码|暴力破解|口令破解|' + _pub.shell('SEC_TEST_PASSWORD') + '|password', '未授权/越权/IDOR': '未授权|越权|水平权限|垂直权限|IDOR|用户枚举|逻辑缺陷|任意用户', 'SQL注入': 'SQL\\s*注入|SQL注入|sql injection', 'XSS': 'XSS|跨站脚本|反射型|存储型|DOM', '文件上传': '文件上传|上传漏洞|webshell|木马|getshell', '任意文件下载/读取': '任意文件下载|任意文件读取|文件下载|目录遍历|路径遍历|任意读取', 'RCE/命令执行/反序列化': '远程代码执行|命令执行|RCE|反序列化|代码执行|Struts|log4j|fastjson', 'SSRF': 'SSRF|服务端请求伪造', '信息泄露': '信息泄露|敏感信息|源码泄露|配置文件|内部IP|路径泄露|手机号|身份证', 'CSRF': 'CSRF|跨站请求伪造', '点击劫持/响应头': '点击劫持|X-Frame|HSTS|响应头|CSP|Referrer|X-Content', 'TLS/SSL/SSH': 'TLS|SSL|证书|CVE-2016-2183|SWEET32|SSH|加密算法|cipher', '组件/CVE': 'CVE-\\d{4}-\\d+|组件|中间件|Redis|MySQL|Zookeeper|RabbitMQ|IceGrid|OpenSSL|glibc|版本', '短信/验证码': '短信|验证码|短信炸弹|轰炸', '上传/下载/文件': '文件'}

def main():
    files = [f for f in sorted(os.listdir(SRC)) if f.endswith('.txt') and (not f.startswith('_'))]
    summary = []
    agg = Counter()
    for fn in files:
        text = open(os.path.join(SRC, fn), encoding='utf-8', errors='replace').read()
        hits = {}
        for (cat, pat) in CATS.items():
            ms = re.findall(pat, text, re.I)
            if ms:
                hits[cat] = len(ms)
                agg[cat] += 1
        names = []
        for line in text.splitlines():
            s = line.strip()
            if 8 <= len(s) <= 120 and re.search('漏洞|弱口令|注入|越权|未授权|泄露|执行|上传|下载|遍历|XSS|CSRF|SSRF|证书|响应头|TLS|SSH|CVE-', s, re.I):
                if s not in names:
                    names.append(s)
        summary.append({'file': fn, 'hits': hits, 'names': names[:60]})
    agg_sorted = agg.most_common()
    lines = ['# 客户漏扫报告关键词汇总', '', '## 类别覆盖文件数', '', '| 类别 | 报告数 |', '|---|---|']
    lines += [f'| {c} | {n} |' for (c, n) in agg_sorted]
    lines += ['', '## 按文件', '']
    for s in summary:
        lines.append(f"### {s['file']}")
        lines.append('- 命中：' + ', '.join((f'{k}({v})' for (k, v) in s['hits'].items())))
        if s['names']:
            lines.append('- 名称/行：')
            lines += ['  - ' + x[:160] for x in s['names'][:25]]
        lines.append('')
    open(OUT_MD, 'w', encoding='utf-8').write('\n'.join(lines))
    json.dump({'aggregate': agg_sorted, 'files': summary}, open(OUT_JSON, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('written', OUT_MD, 'files', len(files))
    print('aggregate', agg_sorted)
if __name__ == '__main__':
    main()
