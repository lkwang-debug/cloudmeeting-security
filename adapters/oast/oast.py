"""OAST 适配器（公共 interactsh）：启动/停止/生成 token/等待回调。
当前实例由 Week 末手动启动；本模块提供状态读取与轮询，供检查插件使用。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
from runner import public_config as _pub
import json
import os
import re
import subprocess
import time
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactsh-client.exe')
STATE = os.path.join(ROOT, 'adapters', 'oast', 'oast_state.json')
LOG = os.path.join(ROOT, 'tools_cache', 'interactsh', 'client.err')
JSONL = os.path.join(ROOT, 'tools_cache', 'interactsh', 'interactions.jsonl')

def status():
    if os.path.exists(STATE):
        return json.load(open(STATE, encoding='utf-8'))
    return {'domain': None, 'pid': None}

def start(server='https://oast.fun'):
    log = open(LOG, 'a', encoding='utf-8')
    p = subprocess.Popen([BIN, '-json', '-o', JSONL, '-v'], stdout=log, stderr=log, close_fds=True, creationflags=8)
    deadline = time.time() + 30
    domain = None
    while time.time() < deadline:
        time.sleep(1)
        try:
            txt = open(LOG, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        m = re.findall('([a-z0-9]{20,}\\.(?:oast\\.fun|oast\\.pro|oast\\.live|interactsh\\.com))', txt)
        if m:
            domain = m[-1]
            break
    state = {'domain': domain, 'pid': p.pid, 'server': server, 'started_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'jsonl': JSONL, 'log': LOG}
    json.dump(state, open(STATE, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    return state

def new_token(label='t'):
    return f'secauto-{label}-{int(time.time() * 1000)}-{os.getpid()}'

def url(token, path='probe'):
    d = status().get('domain')
    if not d:
        raise RuntimeError('OAST 未启动（无 domain）')
    return f'http://{token}.{d}/{path}'

def wait_for(token, timeout=30):
    """轮询 interactions.jsonl，返回匹配 token 的交互列表。"""
    deadline = time.time() + timeout
    hits = []
    while time.time() < deadline:
        if os.path.exists(JSONL):
            with open(JSONL, encoding='utf-8', errors='replace') as f:
                for line in f:
                    if token in line:
                        try:
                            hits.append(json.loads(line))
                        except Exception:
                            pass
        if hits:
            return hits
        time.sleep(2)
    return hits
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['status', 'start', 'url', 'wait'])
    ap.add_argument('arg', nargs='?')
    a = ap.parse_args()
    if a.cmd == 'status':
        print(json.dumps(status(), ensure_ascii=False, indent=1))
    elif a.cmd == 'start':
        print(json.dumps(start(), ensure_ascii=False, indent=1))
    elif a.cmd == 'url':
        print(url(a.arg or new_token()))
    elif a.cmd == 'wait':
        print(json.dumps(wait_for(a.arg), ensure_ascii=False, indent=1)[:2000])
