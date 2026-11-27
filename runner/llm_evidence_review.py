"""C：LLM 证据复核（可插拔）。
- 若配置 SEC_LLM_BASE_URL / SEC_LLM_API_KEY / SEC_LLM_MODEL，则调用 OpenAI 兼容接口；
- 否则生成结构化 prompt + 规则兜底结论（dry-run），便于后续接模型。
输出 reports/final/llm_evidence_review.json
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import time
import requests
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'reports', 'final')
EVIDENCE = {'F-01': ['reports/p3/role_cache_invalidation.json', 'reports/final/regression_role_cache.json'], 'F-02': ['reports/p2/share_api_disclosure.json'], 'F-04': ['reports/p2/client_capture_summary.json'], 'XSS': ['reports/p3/xss_browser_admin02.json'], 'WS': ['reports/p2/ws_webproxy_auth.json'], 'SCENARIO': ['reports/final/scenarios/room_maxuser_boundary.json']}

def read_evidence(files):
    out = {}
    for f in files:
        p = os.path.join(ROOT, f)
        if os.path.exists(p):
            try:
                out[f] = json.load(open(p, encoding='utf-8-sig'))
            except Exception as e:
                out[f] = {'_parse_error': str(e)[:100]}
        else:
            out[f] = None
    return out

def build_prompt(item_id, ev):
    return f'你是云会议系统的安全评审专家。请基于以下证据判断该事项是：已确认漏洞/候选(需产品确认)/误报/信息不足，并给出严重性(Critical/High/Medium/Low/Info)、理由、以及需要补充的证据。只输出 JSON，字段：verdict,severity,confidence,reason,missing_evidence。\n事项：{item_id}\n证据：{json.dumps(ev, ensure_ascii=False)[:6000]}'

def llm_call(prompt):
    base = os.environ.get('SEC_LLM_BASE_URL', '').rstrip('/')
    key = os.environ.get('SEC_LLM_API_KEY', '')
    model = os.environ.get('SEC_LLM_MODEL', 'deepseek-chat')
    if not (base and key):
        return None
    r = requests.post(base + '/chat/completions', headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}, json={'model': model, 'messages': [{'role': 'user', 'content': prompt}], 'temperature': 0}, timeout=60)
    if r.status_code != 200:
        return {'_http': r.status_code, '_body': r.text[:300]}
    txt = (r.json().get('choices') or [{}])[0].get('message', {}).get('content', '')
    try:
        return json.loads(txt[txt.find('{'):txt.rfind('}') + 1])
    except Exception:
        return {'_raw': txt[:500]}

def rule_fallback(item_id, ev):
    """无 LLM 时的规则兜底（与规则版 reviewer 一致）。"""
    f1 = ev.get('reports/p3/role_cache_invalidation.json') or {}
    if item_id == 'F-01':
        ok = 'role_change_test' in f1 and f1.get('role_change_test')
        return {'verdict': '已确认漏洞' if ok else '信息不足', 'severity': 'High', 'confidence': 0.9 if ok else 0.5, 'reason': '降权后旧权限仍生效（TTL=-1，登录未重建缓存）' if ok else '证据字段不足'}
    if item_id == 'F-02':
        return {'verdict': '候选(需产品确认)', 'severity': 'Low-Medium', 'confidence': 0.8, 'reason': '硬编码 Basic 可读取房间信息；是否设计允许需确认'}
    if item_id == 'F-04':
        return {'verdict': '已确认漏洞(既有)', 'severity': 'High', 'confidence': 0.9, 'reason': 'PC 客户端运行时仍用硬编码 OAuth2 凭据'}
    if item_id == 'XSS':
        d = ev.get('reports/p3/xss_browser_admin02.json') or {}
        return {'verdict': '误报/不可利用' if d.get('escaped_img') else '信息不足', 'severity': 'Info', 'confidence': 0.9, 'reason': '昵称被 HTML 转义，OAST 0 回调'}
    if item_id == 'WS':
        return {'verdict': '不构成漏洞', 'severity': 'Info', 'confidence': 0.85, 'reason': '应用层登录校验 token（4098/4104），无鉴权绕过'}
    if item_id == 'SCENARIO':
        return {'verdict': '业务观察(候选)', 'severity': 'Low', 'confidence': 0.6, 'reason': 'maxUserCount 可设到 50000，需产品规则确认'}
    return {'verdict': '信息不足', 'severity': 'Info', 'confidence': 0.3}

def main():
    os.makedirs(OUT, exist_ok=True)
    result = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'model': os.environ.get('SEC_LLM_MODEL', 'deepseek-chat'), 'mode': 'llm' if os.environ.get('SEC_LLM_BASE_URL') and os.environ.get('SEC_LLM_API_KEY') else 'dry_run', 'items': []}
    for (item_id, files) in EVIDENCE.items():
        ev = read_evidence(files)
        prompt = build_prompt(item_id, ev)
        llm = llm_call(prompt)
        result['items'].append({'id': item_id, 'files': files, 'llm': llm if llm else None, 'fallback': rule_fallback(item_id, ev), 'prompt_chars': len(prompt)})
        print(item_id, 'mode:', result['mode'], 'llm:', bool(llm), 'fallback:', result['items'][-1]['fallback']['verdict'])
    json.dump(result, open(os.path.join(OUT, 'llm_evidence_review.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('written:', os.path.join(OUT, 'llm_evidence_review.json'))
if __name__ == '__main__':
    main()
