"""V8 P1：服务器/中间件配置基线核查（只读，SSH 155）。
输出 reports/final/server_baseline.json + SERVER_BASELINE.md
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import paramiko
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'reports', 'final')

def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(_pub.env('SEC_SSH_HOST', ''), 22, _pub.env('SEC_SSH_USER'), _pub.env('SEC_SSH_PASSWORD', ''), timeout=10)

    def run(cmd, t=120):
        (i, o, e) = c.exec_command(cmd, timeout=t)
        return (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
    data = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'host': _pub.env('SEC_SSH_HOST', '')}
    data['listening'] = run('ss -lnt 2>/dev/null | head -60')
    data['docker_ports'] = run("docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | head -40")
    data['ssh_config'] = run("grep -E '^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding)' /etc/ssh/sshd_config 2>/dev/null")
    data['os'] = run('cat /etc/os-release 2>/dev/null | head -4')
    data['redis_bind'] = run("docker inspect hst-redis --format '{{json .HostConfig.PortBindings}}' 2>/dev/null")
    data['mysql_bind'] = run("docker inspect hst-mysql --format '{{json .HostConfig.PortBindings}}' 2>/dev/null")
    data['nginx_headers'] = run("docker exec hst-nginx nginx -T 2>/dev/null | grep -Ei 'server_tokens|add_header|ssl_protocols|ssl_ciphers' | head -20")
    data['firewall'] = run('systemctl is-active firewalld 2>/dev/null; iptables -S 2>/dev/null | head -10')
    data['docker_version'] = run("docker version --format '{{.Server.Version}}' 2>/dev/null")
    c.close()
    obs = []
    if 'PermitRootLogin yes' in data['ssh_config']:
        obs.append('SSH 允许 root 直接登录（内网环境，建议限制）')
    if 'PasswordAuthentication yes' in data['ssh_config']:
        obs.append('SSH 开启密码认证（建议密钥/跳板）')
    if data['docker_ports'] and ('0.0.0.0' in data['docker_ports'] or ':::' in data['docker_ports']):
        obs.append('存在容器端口映射到 0.0.0.0（需确认是否仅内网可达）')
    if 'server_tokens' not in data['nginx_headers'].lower():
        obs.append('nginx 未显式关闭 server_tokens（版本信息可能暴露）')
    data['observations'] = obs
    json.dump(data, open(os.path.join(OUT, 'server_baseline.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    lines = ['# 服务器/中间件配置基线（只读）', '', f"- 时间：{data['generated_at']}", f"- 主机：{data['host']}", f"- Docker：{data['docker_version']}", '', '## 观察项', *[f'- {o}' for o in obs], '', '## 监听端口（节选）', '```', data['listening'][:1500], '```', '', '## 容器端口映射', '```', data['docker_ports'][:1500], '```', '', '## SSH 配置', '```', data['ssh_config'], '```', '', '## nginx 安全相关配置', '```', data['nginx_headers'][:1200], '```']
    open(os.path.join(OUT, 'SERVER_BASELINE.md'), 'w', encoding='utf-8').write('\n'.join(lines))
    print('observations:', len(obs), '->', OUT)
if __name__ == '__main__':
    main()
