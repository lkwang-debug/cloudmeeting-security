"""中间件：常见未授权服务探测（Elasticsearch/MQTT/ActiveMQ/Prometheus/Grafana）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import socket
import time
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
HOSTS = os.environ.get('GATE_MW_HOSTS', '' + _pub.shell('SEC_DB_HOST') + ',' + _pub.shell('SEC_DB_HOST') + '').split(',')
PROBES = [('elasticsearch', 9200, 'http', '/_cat/indices?format=json', 'high'), ('prometheus', 9090, 'http', '/-/healthy', 'high'), ('grafana', 3000, 'http', '/api/health', 'medium'), ('activemq', 8161, 'http', '/admin/', 'medium'), ('flink', 8082, 'http', '/overview', 'high')]

def main():
    (findings, out) = ([], [])
    for host in [h.strip() for h in HOSTS if h.strip()]:
        for (name, port, proto, path, sev) in PROBES:
            try:
                s = socket.create_connection((host, port), timeout=2)
                s.close()
            except Exception:
                continue
            item = {'host': host, 'service': name, 'port': port}
            if proto == 'http':
                try:
                    r = requests.get(f'http://{host}:{port}{path}', timeout=5, verify=False)
                    item.update({'http': r.status_code, 'len': len(r.text or '')})
                    body = (r.text or '').lower()
                    if r.status_code == 200 and name == 'elasticsearch' and ('health' in body or 'index' in body):
                        findings.append(gc.finding('MW-ES-UNAUTH', 'high', f'{host}:{port} Elasticsearch 未授权', evidence=body[:250], remediation='启用认证/仅内网'))
                    elif r.status_code == 200 and name == 'prometheus' and ('prometheus' in body or 'healthy' in body):
                        findings.append(gc.finding('MW-PROM-UNAUTH', 'high', f'{host}:{port} Prometheus 未授权', evidence=body[:250], remediation='启用认证/仅内网'))
                    elif name == 'grafana' and r.status_code == 200 and ('database' in body):
                        findings.append(gc.finding('MW-GRAFANA-EXPOSED', 'medium', f'{host}:{port} Grafana 暴露', evidence=body[:200], remediation='仅内网/强认证'))
                    elif name == 'flink' and r.status_code == 200 and ('flink' in body or 'taskmanager' in body):
                        findings.append(gc.finding('MW-FLINK-EXPOSED', 'high', f'{host}:{port} Flink 控制台暴露', evidence=body[:200], remediation='启用认证/仅内网'))
                    elif name == 'activemq' and 'activeMQ' in body:
                        findings.append(gc.finding('MW-ACTIVEMQ-EXPOSED', 'medium', f'{host}:{port} ActiveMQ 控制台暴露', evidence=body[:200], remediation='禁用控制台/强认证'))
                except Exception as e:
                    item['error'] = str(e)[:80]
            out.append(item)
    for host in [h.strip() for h in HOSTS if h.strip()]:
        try:
            s = socket.create_connection((host, 1883), timeout=2)
            s.close()
            out.append({'host': host, 'service': 'mqtt', 'port': 1883, 'reachable': True})
            findings.append(gc.finding('MW-MQTT-EXPOSED', 'medium', f'{host}:1883 MQTT 端口开放', evidence='TCP reachable', remediation='启用认证/仅内网'))
        except Exception:
            pass
    gc.emit('middleware_extra', 'middleware', 'PASS', findings, summary=json.dumps({'probes': out}, ensure_ascii=False)[:900])
if __name__ == '__main__':
    main()
