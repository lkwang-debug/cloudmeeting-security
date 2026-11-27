"""应用安全：历史客户报告中的已知接口/漏洞链路（只读 POC，不做写操作）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import base64
import json
import time
import requests
import urllib3
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc
urllib3.disable_warnings()
BASE = gc.base_url()
BASIC = 'Basic ' + base64.b64encode((_pub.env('SEC_CLIENT_ID') + ':' + _pub.env('SEC_CLIENT_SECRET')).encode()).decode()
UA = {'User-Agent': 'Mozilla/5.0', 'Origin': BASE}

def post(path, **kw):
    try:
        return requests.post(BASE + path, params={'t': str(int(time.time() * 1000))}, timeout=12, verify=False, **kw)
    except Exception:
        return None

def main():
    (findings, probes) = ([], [])

    def add(pid, sev, title, evidence, fix):
        findings.append(gc.finding(pid, sev, title, evidence=str(evidence)[:400], remediation=fix))
    soap = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dbup="http://DBUpdate.webservice.gtone3.com"><soapenv:Header/><soapenv:Body><dbup:GetNodeInfo/></soapenv:Body></soapenv:Envelope>'
    r = post('/GToneServices3.5/services/GToneWebServices', data=soap, headers={**UA, 'Content-Type': 'text/xml;charset=UTF-8', 'SOAPAction': ''})
    probes.append({'path': 'GToneWebServices/GetNodeInfo', 'http': getattr(r, 'status_code', None)})
    if r is not None and r.status_code == 200 and any((k in (r.text or '').lower() for k in ('nodeid', 'node_id'))):
        add('LEGACY-SOAP-NODEID', 'high', '历史 SOAP GetNodeInfo 未授权返回 nodeID', (r.text or '')[:300], '关闭/鉴权 GToneWebServices；升级版本')
    empty = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dbup="http://DBUpdate.webservice.gtone3.com"><soapenv:Header/><soapenv:Body><dbup:AllUser><dbup:in0></dbup:in0></dbup:AllUser></soapenv:Body></soapenv:Envelope>'
    r = post('/GToneServices3.5/services/GToneWebServices', data=empty, headers={**UA, 'Content-Type': 'text/xml;charset=UTF-8', 'SOAPAction': ''})
    probes.append({'path': 'GToneWebServices/AllUser-empty', 'http': getattr(r, 'status_code', None)})
    if r is not None and r.status_code == 500 and ('NullPointerException' in (r.text or '')):
        add('LEGACY-SOAP-ADDUSER', 'high', '历史 batchAddUser/AllUser 未授权链路可触发', '500 java.lang.NullPointerException', '升级版本；接口鉴权；删除默认 keyCode')
    r = post('/fmapi/servers/addresses', headers={**UA, 'Content-Type': 'application/json'}, json={})
    probes.append({'path': '/fmapi/servers/addresses', 'http': getattr(r, 'status_code', None)})
    if r is not None and r.status_code == 200 and any((k in (r.text or '').lower() for k in ('servers', 'address', 'ftp', 'appkey'))):
        add('LEGACY-FMAPI-ADDRESS', 'high', 'fmapi/servers/addresses 未授权泄露 API/FTP 地址', (r.text or '')[:300], '接口鉴权；移除 FTP 凭据；签名校验')
    for rid in (10000, 10001):
        r = post('/meeting-resource-server/open/rooms/getroominfo', headers={**UA, 'Authorization': BASIC, 'Content-Type': 'application/x-www-form-urlencoded'}, data={'roomId': rid})
        probes.append({'path': '/open/rooms/getroominfo', 'roomId': rid, 'http': getattr(r, 'status_code', None)})
        if r is not None and r.status_code == 200:
            try:
                j = r.json()
            except Exception:
                j = {}
            if j.get('code') in (0, '0', 1, '1') and (j.get('result') or j.get('data')):
                add('LEGACY-ROOM-ENUM', 'high', f'open/getroominfo 未授权读取会议室 roomId={rid}', json.dumps(j, ensure_ascii=False)[:300], '接口改用 Bearer+鉴权；roomId 使用 UUID')
    for uid in (1, 2):
        r = requests.get(BASE + '/meeting-resource-server/open/paasAuthInfo', headers={**UA, 'Authorization': BASIC}, params={'userId': uid}, timeout=12, verify=False)
        probes.append({'path': '/open/paasAuthInfo', 'userId': uid, 'http': getattr(r, 'status_code', None)})
        text = r.text or ''
        if r.status_code == 200 and any((k in text.lower() for k in ('token', 'media'))):
            add('LEGACY-PAAS-IDOR', 'high', f'paasAuthInfo 用 userId={uid} 可获取媒体 Token', text[:300], 'userId 从会话取；HMAC 签名；权限校验')
    gc.emit('legacy_poc', 'application', 'PASS', findings, summary=json.dumps({'probes': probes}, ensure_ascii=False)[:900])
if __name__ == '__main__':
    main()
