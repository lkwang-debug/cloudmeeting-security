"""中间件服务级只读探测：MySQL/Redis/RabbitMQ/ZooKeeper/IceGrid。
优先经 SSH 155 在容器/主机侧探测（本地网络常不可直达），全部只读。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import socket
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
ROOT = gc.ROOT
HOST = os.environ.get('GATE_MW_HOST', _pub.env('SEC_SSH_HOST', ''))
SSH = {'host': _pub.env('SEC_SSH_HOST', ''), 'user': _pub.env('SEC_SSH_USER'), 'pass': os.environ.get('SEC_HOST_PASS', _pub.env('SEC_SSH_PASSWORD', ''))}

def ssh_run(cmd, timeout=30):
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(SSH['host'], 22, SSH['user'], SSH['pass'], timeout=8)
        (i, o, e) = c.exec_command(cmd, timeout=timeout)
        out = (o.read().decode('utf-8', 'replace') + e.read().decode('utf-8', 'replace')).strip()
        c.close()
        return out
    except Exception as ex:
        return 'ERR:' + str(ex)[:120]

def probe_redis(findings):
    ping = ssh_run('docker exec hst-redis redis-cli -h ' + _pub.shell('SEC_DB_HOST') + ' -p 22002 ping 2>&1')
    out = {'noauth_ping': ping[:120]}
    if 'PONG' in ping:
        findings.append(gc.finding('MW-REDIS-UNAUTH', 'critical', 'Redis 未授权可 PING（无密码）', evidence=ping[:120], remediation='启用 requirepass/ACL'))
        out['unauth'] = True
    elif 'NOAUTH' in ping or 'AUTH' in ping.upper():
        out['unauth'] = False
        info = ssh_run('docker exec hst-redis redis-cli -h ' + _pub.shell('SEC_DB_HOST') + ' -p 22002 -a ' + _pub.shell('SEC_REDIS_PASSWORD') + ' info server 2>/dev/null | head -5')
        out['info'] = info[:200]
        out['config_maxmemory'] = ssh_run('docker exec hst-redis redis-cli -h ' + _pub.shell('SEC_DB_HOST') + ' -p 22002 -a ' + _pub.shell('SEC_REDIS_PASSWORD') + ' config get maxmemory 2>/dev/null')[:120]
    out['bind'] = ssh_run('docker exec hst-redis sh -c \'grep -E "^bind|^port|^requirepass" /etc/redis/redis.conf 2>/dev/null\' | head -3')
    return out

def probe_zk(findings):
    cmd = "timeout 2 bash -c 'exec 3<>/dev/tcp/" + _pub.shell('SEC_DB_HOST') + "/22006; printf ruok >&3; head -c 120 <&3' 2>&1"
    out = {'ruok': ssh_run(cmd, timeout=10)[:200]}
    if 'imok' in out['ruok']:
        findings.append(gc.finding('MW-ZK-UNAUTH', 'high', 'ZooKeeper 4lw 未授权（ruok=imok）', evidence=out['ruok'], remediation='启用 4lw 白名单/ACL'))
        out['unauth'] = True
    else:
        out['unauth'] = False
    out['port'] = ssh_run("ss -lnt 2>/dev/null | grep -E ':22006' | head -1")
    return out

def probe_rabbit(findings):
    out = {}
    listeners = ssh_run('docker exec hst-rabbitmq rabbitmq-diagnostics -q listeners 2>&1 | head -20')
    out['listeners'] = listeners[:400]
    py = "python3 - <<'PY'\nimport urllib.request\ntry:\n r=urllib.request.urlopen('http://127.0.0.1:15672/api/overview',timeout=3)\n print('HTTP',r.status)\nexcept Exception as e:\n print('ERR',str(e)[:100])\nPY"
    out['mgmt'] = ssh_run('docker exec hst-rabbitmq sh -c ' + json.dumps(py), timeout=20)[:250]
    if 'HTTP 200' in out['mgmt']:
        findings.append(gc.finding('MW-RABBITMQ-UNAUTH', 'high', 'RabbitMQ 管理 API 未授权可访问', evidence=out['mgmt'], remediation='管理端口鉴权/仅内网/改默认 guest'))
        out['unauth'] = True
    else:
        out['unauth'] = False
    return out

def probe_ice(findings):
    out = {}
    cfg = ssh_run("docker exec hst-icegridregistry cat /etc/conf/icegridregistry.conf 2>/dev/null | grep -Ei 'Endpoints|Registry' | head -10", timeout=20)
    out['config_endpoints'] = cfg[:400]
    ports = [int(x) for x in __import__('re').findall('-p\\s*(\\d+)', cfg)] + [22014, 4061]
    for port in dict.fromkeys(ports):
        r = ssh_run(("timeout 2 bash -c 'exec 3<>/dev/tcp/" + _pub.shell('SEC_DB_HOST') + "/%d' 2>/dev/null && echo ok") % port, timeout=8)
        if 'ok' in r:
            out['reachable_port'] = port
            break
    if 'reachable_port' not in out:
        findings.append(gc.finding('MW-ICEGRID-UNREACHABLE', 'medium', 'IceGrid registry 端口不可达/未确认', evidence=cfg[:200], remediation='确认 registry 端口与网络'))
    return out

def main():
    findings = []
    checks = {'host': HOST, 'redis': probe_redis(findings), 'zookeeper': probe_zk(findings), 'rabbitmq': probe_rabbit(findings), 'icegrid': probe_ice(findings)}
    try:
        s = socket.create_connection((HOST, 22007), timeout=5)
        b = s.recv(64)
        s.close()
        checks['mysql'] = {'banner': b.decode('utf-8', 'replace')[:100], 'reachable': True}
    except Exception as e:
        checks['mysql'] = {'reachable': False, 'error': str(e)[:80]}
        findings.append(gc.finding('MW-MYSQL-UNREACHABLE', 'medium', 'MySQL 端口不可达', evidence=str(e)[:120], remediation='确认网络/端口'))
    errors = [k for (k, v) in checks.items() if isinstance(v, dict) and v.get('error')]
    if errors:
        findings.append(gc.finding('MW-PARTIAL', 'medium', f"部分中间件探测异常: {', '.join(errors)}", evidence=json.dumps(checks, ensure_ascii=False)[:400]))
    gc.emit('middleware_scan', 'middleware', 'PASS', findings, summary=json.dumps(checks, ensure_ascii=False)[:900])
if __name__ == '__main__':
    main()
