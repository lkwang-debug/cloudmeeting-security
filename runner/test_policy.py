"""验证编排层策略：read_only / resume / abort / budget（临时改配置，结束恢复）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import shutil
import subprocess
import sys
import time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = os.path.join(ROOT, 'configs', 'execution_policy.yaml')
BAK = CFG + '.bak'
PY = sys.executable
ORCH = os.path.join(ROOT, 'runner', 'orchestrator.py')
STATE = os.path.join(ROOT, 'state', 'orchestrator_state.json')
ABORT = os.path.join(ROOT, 'state', 'ABORT')
OUT = os.path.join(ROOT, 'reports', 'final', 'orchestrator_policy_tests.json')

def run(args):
    p = subprocess.run([PY, ORCH] + args, cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=600)
    return (p.returncode, (p.stdout or '')[-600:])

def read_run():
    try:
        return json.load(open(os.path.join(ROOT, 'reports', 'final', 'orchestrator_run.json'), encoding='utf-8'))
    except Exception:
        return {}

def skips(res):
    return {s['name']: s.get('skipped') for s in res.get('steps') or [] if s.get('skipped')}

def main():
    shutil.copy2(CFG, BAK)
    out = {'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'tests': {}}
    try:
        t = open(CFG, encoding='utf-8').read().replace('read_only: false', 'read_only: true')
        open(CFG, 'w', encoding='utf-8').write(t)
        (rc, log) = run(['--plan', 'smoke', '--reset'])
        res = read_run()
        out['tests']['read_only'] = {'rc': rc, 'skips': skips(res), 'pass': skips(res).get('scenario_room_maxuser') == 'read_only_policy'}
        open(CFG, 'w', encoding='utf-8').write(open(BAK, encoding='utf-8').read())
        run(['--plan', 'smoke', '--reset'])
        (rc, log) = run(['--plan', 'smoke'])
        res = read_run()
        sk = skips(res)
        out['tests']['resume'] = {'rc': rc, 'skips': sk, 'pass': all((v == 'already_completed' for v in sk.values())) and len(sk) > 0}
        open(ABORT, 'w', encoding='utf-8').write('test abort')
        (rc, log) = run(['--plan', 'smoke', '--reset'])
        res = read_run()
        sk = skips(res)
        out['tests']['abort'] = {'rc': rc, 'skips': sk, 'pass': any((v == 'abort_file' for v in sk.values()))}
        if os.path.exists(ABORT):
            os.remove(ABORT)
        txt = open(BAK, encoding='utf-8').read().replace('max_plugins: 20', 'max_plugins: 1')
        open(CFG, 'w', encoding='utf-8').write(txt)
        (rc, log) = run(['--plan', 'smoke', '--reset'])
        res = read_run()
        sk = skips(res)
        out['tests']['budget'] = {'rc': rc, 'skips': sk, 'pass': any((v == 'budget_max_plugins' for v in sk.values()))}
    finally:
        shutil.copy2(BAK, CFG)
        if os.path.exists(ABORT):
            os.remove(ABORT)
    out['summary'] = {k: v['pass'] for (k, v) in out['tests'].items()}
    json.dump(out, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps(out['summary'], ensure_ascii=False))
if __name__ == '__main__':
    main()
