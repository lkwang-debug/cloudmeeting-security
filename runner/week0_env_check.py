"""Week0 环境核查：worker / 工具 / OAST / 目标只读 / 账号 / 写白名单，输出 JSON+MD 报告。
只做只读检查，不修改目标环境，不安装工具。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import datetime
import urllib.request
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, 'reports', 'week0')
TARGET = _pub.target()
SSH_HOSTS = [_pub.env('SEC_SSH_HOST', ''), _pub.env('SEC_SSH_HOST', '')]

def sh(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or '') + (p.stderr or '')
    except Exception as e:
        return f'ERROR: {e}'

def has_cmd(name):
    return shutil.which(name) is not None

def tcp(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except Exception:
        return False

def http(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except Exception as e:
        return f'ERROR:{type(e).__name__}'

def ssh_read(host, cmds):
    """只读 SSH 采集；仅固定命令。"""
    out = {}
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, 22, 'root', os.environ.get('SEC_SSH_PASS', _pub.env('SEC_SSH_PASSWORD', '')), timeout=8, banner_timeout=8, auth_timeout=8)
        for (k, cmd) in cmds.items():
            try:
                (_, o, e) = c.exec_command(cmd, timeout=20)
                out[k] = (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()[:500]
            except Exception as ex:
                out[k] = f'ERROR:{ex}'
        c.close()
    except Exception as e:
        out['error'] = str(e)[:200]
    return out

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    r = {'generated_at': datetime.datetime.now().isoformat(timespec='seconds'), 'host': platform.node(), 'python': sys.version.split()[0]}
    r['worker'] = {'wsl': sh('wsl --status', 8).strip()[:300] if has_cmd('wsl') else 'NOT_INSTALLED', 'docker': sh('docker --version', 8).strip() if has_cmd('docker') else 'NOT_INSTALLED', 'java': sh('java -version', 8).strip()[:200] if has_cmd('java') else 'NOT_INSTALLED', 'java17': 'unknown', 'tools': {t: has_cmd(t) for t in ('zap.sh', 'nuclei', 'testssl.sh', 'sqlmap', 'interactsh-client', 'syft', 'grype', 'git', 'curl')}, 'note': 'ZAP 需要 Java 17+；本机 Java 1.8 且无 Docker/WSL 时 ZAP 后置'}
    r['worker']['java17'] = 'yes' if '17' in r['worker']['java'] or '21' in r['worker']['java'] else 'no'
    r['target'] = {'https_28443': http(TARGET + '/'), 'http_28080': http('http://example.test:28080/'), 'tcp_28443': tcp(_pub.web_host(), 28443), 'tcp_28080': tcp(_pub.web_host(), 28080), 'tcp_22_155': tcp(_pub.env('SEC_SSH_HOST', ''), 22)}
    r['target_hosts'] = {}
    for h in SSH_HOSTS:
        r['target_hosts'][h] = ssh_read(h, {'os': 'cat /etc/os-release 2>/dev/null | grep PRETTY_NAME', 'arch': 'uname -m', 'nginx_version': 'docker exec hst-nginx nginx -v 2>&1', 'ports': "ss -lntp | grep -E ':28443|:28080' | head -3", 'disk': 'df -h /hst | tail -1'})
    r['gaps'] = {'oast': '未配置（需自建 interactsh + 公网入口）' if not os.environ.get('SEC_OAST_DOMAIN') else 'configured', 'accounts': {'backend_token': 'env SEC_BACKEND_USER/SEC_BACKEND_PASS 未设置' if not os.environ.get('SEC_BACKEND_USER') else 'configured', 'oauth2': 'env SEC_CLIENT_ID/SEC_CLIENT_SECRET 未设置' if not os.environ.get('SEC_CLIENT_ID') else 'configured', 'open_api': 'env SEC_OPEN_KEY/SEC_OPEN_SECRET 未设置' if not os.environ.get('SEC_OPEN_KEY') else 'configured', 'fmapi': 'env SEC_FMAPI_APPKEY 未设置' if not os.environ.get('SEC_FMAPI_APPKEY') else 'configured'}, 'write_whitelist': 'disabled（authorization_policy.yaml write_policy.enabled=false）', 'worker': '需 WSL2+Docker 或独立 Linux 测试机（当前无 Docker）'}
    blockers = []
    if r['worker']['docker'] == 'NOT_INSTALLED' and 'wsl' not in r['worker']['wsl'].lower():
        blockers.append('隔离 worker 未就绪（无 Docker/WSL）→ ZAP/nuclei/testssl 后置')
    if r['gaps']['oast'].startswith('未配置'):
        blockers.append('OAST 未配置 → SSRF/XXE 盲测阻塞')
    if any((v.startswith('env ') for v in r['gaps']['accounts'].values())):
        blockers.append('账号池未注入 → 认证 POC 只能用临时测试账号')
    r['blockers'] = blockers
    with open(os.path.join(OUT_DIR, 'week0_env_check.json'), 'w', encoding='utf-8') as f:
        json.dump(r, f, ensure_ascii=False, indent=1)
    md = ['# Week0 环境核查报告', '', f"- 生成时间：{r['generated_at']}", f"- 主机：{r['host']} / Python {r['python']}", '', '## 1. 隔离 worker 与工具', '', f"- WSL：{r['worker']['wsl']}", f"- Docker：{r['worker']['docker']}", f"- Java：{r['worker']['java'][:100]}（Java17：{r['worker']['java17']}）", f"- 安全工具：{r['worker']['tools']}", '', '## 2. 目标可达性', '', f"- HTTPS 28443：{r['target']['https_28443']}；HTTP 28080：{r['target']['http_28080']}", f"- TCP 28443：{r['target']['tcp_28443']}；TCP 28080：{r['target']['tcp_28080']}；SSH 155：{r['target']['tcp_22_155']}", '', '## 3. 目标机只读采集', '']
    for (h, d) in r['target_hosts'].items():
        md.append(f'### {h}')
        md.append('```json')
        md.append(json.dumps(d, ensure_ascii=False, indent=1)[:1500])
        md.append('```')
    md += ['', '## 4. 缺口', ''] + [f'- {k}：{v}' for (k, v) in r['gaps'].items()]
    md += ['', '## 5. 阻断项', ''] + [f'- {b}' for b in blockers] if blockers else ['无']
    with open(os.path.join(OUT_DIR, 'week0_env_check.md'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(md))
    print(json.dumps({'blockers': blockers, 'out': OUT_DIR}, ensure_ascii=False, indent=1))
if __name__ == '__main__':
    main()
