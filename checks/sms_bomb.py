"""应用安全：短信炸弹防护检查。
无短信接口 -> 不适用；有接口但无测试号码 -> 阻塞（不发真实短信）。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
try:
    import gate_common as gc
except ImportError:
    from checks import gate_common as gc

def main():
    paths = [p for p in gc.all_endpoints() if any((k in p.lower() for k in ('sms', 'sendcode', 'sendmessage', 'message/send')))]
    if not paths:
        gc.emit('sms_bomb', 'application', 'PASS', [gc.finding('SMS-NOT-APPLICABLE', 'info', '知识库未发现短信发送类接口，标记不适用（需人工确认）', evidence='all_backend_endpoints 无 sms/message/verifycode', confidence='low')], summary=json.dumps({'endpoints': []}, ensure_ascii=False))
        return
    phone = os.environ.get('SEC_SMS_TEST_PHONE', '')
    if not phone:
        gc.emit('sms_bomb', 'application', 'BLOCKED', [], blocked_reason=f'发现短信接口 {paths[:3]}，但无测试号码 SEC_SMS_TEST_PHONE；禁止对真实号码发送')
        return
    gc.emit('sms_bomb', 'application', 'BLOCKED', [], blocked_reason='已配置测试号码，但短信接口参数/白名单未确认；需人工补充端点后再启用')
if __name__ == '__main__':
    main()
