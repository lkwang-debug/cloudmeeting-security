"""中间件/主机：Linux 安全基线只读检查（客户基线报告常见项）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import paramiko
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
HOSTS = os.environ.get('GATE_BASELINE_HOSTS', '' + _pub.shell('SEC_DB_HOST') + ',' + _pub.shell('SEC_DB_HOST') + '').split(',')
USER = os.environ.get('GATE_SSH_USER', 'root')
PWD_MAP = {_pub.env('SEC_SSH_HOST', ''): os.environ.get('GATE_SSH_PASS_155', _pub.env('SEC_SSH_PASSWORD', '')), _pub.env('SEC_SSH_HOST', ''): os.environ.get('GATE_SSH_PASS_180', 'FsMeeting.com')}

def ssh(host, cmd, timeout=20):
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, 22, USER, PWD_MAP.get(host, ''), timeout=8)
        (i, o, e) = c.exec_command(cmd, timeout=timeout)
        out = (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
        c.close()
        return out
    except Exception as e:
        return 'ERR:' + str(e)[:120]

def main():
    (findings, out) = ([], [])
    for host in [h.strip() for h in HOSTS if h.strip()]:
        info = {'host': host}
        sshd = ssh(host, "grep -E '^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding|ClientAliveInterval|ClientAliveCountMax)' /etc/ssh/sshd_config 2>/dev/null")
        info['sshd'] = sshd
        if 'PermitRootLogin yes' in sshd:
            findings.append(gc.finding('BASELINE-SSH-ROOT', 'medium', f'{host} 允许 root 直接 SSH 登录', evidence=sshd[:300], remediation='PermitRootLogin no'))
        if 'PasswordAuthentication yes' in sshd:
            findings.append(gc.finding('BASELINE-SSH-PWD', 'medium', f'{host} SSH 开启密码认证', evidence=sshd[:300], remediation='使用密钥/跳板；限制来源 IP'))
        if 'PermitEmptyPasswords yes' in sshd:
            findings.append(gc.finding('BASELINE-SSH-EMPTY', 'high', f'{host} SSH 允许空口令', evidence=sshd[:300], remediation='PermitEmptyPasswords no'))
        if 'ClientAliveInterval' not in sshd:
            findings.append(gc.finding('BASELINE-SSH-TIMEOUT', 'low', f'{host} SSH 未配置会话超时', evidence=sshd[:300], remediation='ClientAliveInterval=600'))
        policy = ssh(host, "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN)' /etc/login.defs 2>/dev/null")
        info['password_policy'] = policy
        for line in policy.splitlines():
            if line.startswith('PASS_MAX_DAYS'):
                try:
                    if int(line.split()[-1]) > 90:
                        findings.append(gc.finding('BASELINE-PWD-MAX', 'medium', f'{host} 口令最长有效期超过90天', evidence=line, remediation='PASS_MAX_DAYS 90'))
                except Exception:
                    pass
            if line.startswith('PASS_MIN_LEN'):
                try:
                    if int(line.split()[-1]) < 8:
                        findings.append(gc.finding('BASELINE-PWD-LEN', 'medium', f'{host} 口令最小长度小于8', evidence=line, remediation='PASS_MIN_LEN 8+'))
                except Exception:
                    pass
        selinux = ssh(host, 'getenforce 2>/dev/null')
        info['selinux'] = selinux
        if selinux.strip().lower() == 'disabled':
            findings.append(gc.finding('BASELINE-SELINUX', 'medium', f'{host} SELinux 未启用', evidence=selinux, remediation='启用 enforcing/permissive'))
        audit = ssh(host, 'systemctl is-active auditd 2>/dev/null')
        info['auditd'] = audit
        if audit.strip() != 'active':
            findings.append(gc.finding('BASELINE-AUDITD', 'medium', f'{host} auditd 未运行', evidence=audit, remediation='启用 auditd 并配置规则'))
        out.append(info)
    gc.emit('host_baseline', 'middleware', 'PASS', findings, summary=json.dumps({'hosts': out}, ensure_ascii=False)[:1000])
if __name__ == '__main__':
    main()
