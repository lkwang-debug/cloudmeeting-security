"""应用安全：SOAP jaxws 未授权/默认 keyCode 检查。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import hashlib
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
WSDL = '/fmapi/webservice/jaxws?wsdl'
DEFAULT_KEY = hashlib.md5(b'fswebservice2011').hexdigest().upper()
SOAP = f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.ces.hst.com/">\n<soapenv:Header/><soapenv:Body><web:getUserinfoList>\n<serachKey></serachKey><serachType>0</serachType><currPage>1</currPage><pageSize>1</pageSize>\n<keyCode>{DEFAULT_KEY}</keyCode></web:getUserinfoList></soapenv:Body></soapenv:Envelope>'

def main():
    findings = []
    checks = {'default_key': DEFAULT_KEY}
    try:
        r = requests.get(BASE + WSDL, timeout=15, verify=False, headers={'User-Agent': 'Mozilla/5.0', 'Origin': BASE})
        checks['wsdl_http'] = r.status_code
        checks['wsdl_len'] = len(r.text or '')
        checks['wsdl_unauth'] = r.status_code == 200 and 'definitions' in (r.text or '').lower()
        if checks['wsdl_unauth']:
            findings.append(gc.finding('SOAP-WSDL-UNAUTH', 'high', 'SOAP WSDL 未授权可访问', evidence=(r.text or '')[:300], remediation='关闭 WSDL/增加鉴权；默认 keyCode 强制修改'))
    except Exception as e:
        checks['wsdl_error'] = str(e)[:100]
    try:
        r = requests.post(BASE + '/fmapi/webservice/jaxws', data=SOAP, headers={'Content-Type': 'text/xml;charset=UTF-8', 'SOAPAction': '', 'User-Agent': 'Mozilla/5.0', 'Origin': BASE}, params={'t': str(int(time.time() * 1000))}, timeout=15, verify=False)
        text = r.text or ''
        checks['soap_http'] = r.status_code
        checks['soap_len'] = len(text)
        checks['soap_has_user'] = any((k in text.lower() for k in ('username', 'userinfo', 'getuserinfolistresult')))
        if r.status_code == 200 and checks['soap_has_user']:
            findings.append(gc.finding('SOAP-DEFAULT-KEYCODE', 'high', 'SOAP 默认 keyCode 可调用 getUserinfoList（未授权取用户数据）', evidence=text[:400], remediation='修改默认 keyCode；接口鉴权/白名单'))
    except Exception as e:
        checks['soap_error'] = str(e)[:100]
    gc.emit('soap_checks', 'application', 'PASS', findings, summary=json.dumps(checks, ensure_ascii=False)[:500])
if __name__ == '__main__':
    main()
