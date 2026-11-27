"""V8 编排层（最小可用）：策略、预算、限速、断点恢复、只读守卫、插件执行。
用法：
  python runner/orchestrator.py --plan smoke
  python runner/orchestrator.py --plan smoke --reset
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import argparse
import json
import os
import subprocess
import sys
import time
import yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
POLICY = os.path.join(ROOT, 'configs', 'execution_policy.yaml')
OUT = os.path.join(ROOT, 'reports', 'final', 'orchestrator_run.json')
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from runner.plugin_registry import PLUGINS
from checks.plugin_base import CliPlugin

def load_gating():
    """读取条件检测门控（detect_candidates + scope execution）。"""
    import yaml
    gating = {}
    cand = os.path.join(ROOT, 'knowledge', 'detect_candidates.json')
    if os.path.exists(cand):
        try:
            gating.update(json.load(open(cand, encoding='utf-8')).get('gating') or {})
        except Exception:
            pass
    scope_path = os.path.join(ROOT, 'configs', 'scope.yaml')
    if os.path.exists(scope_path):
        try:
            scope = yaml.safe_load(open(scope_path, encoding='utf-8')) or {}
            ex = scope.get('execution') or {}
            if (ex.get('ssrf') or {}).get('enabled'):
                gating['ssrf_xxe'] = True
            if (ex.get('race') or {}).get('enabled'):
                gating['race'] = True
            if (ex.get('longconn') or {}).get('enabled'):
                gating['long_connection'] = True
        except Exception:
            pass
    return gating

def load_policy():
    return yaml.safe_load(open(POLICY, encoding='utf-8'))

def load_state(path):
    if os.path.exists(path):
        try:
            return json.load(open(path, encoding='utf-8'))
        except Exception:
            pass
    return {'completed': {}, 'runs': []}

def save_state(path, state):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(state, open(path, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plan', default='smoke')
    ap.add_argument('--reset', action='store_true')
    args = ap.parse_args()
    pol = load_policy()
    state_path = os.path.join(ROOT, pol['state']['path'])
    state = load_state(state_path)
    if args.reset:
        state = {'completed': {}, 'runs': []}
        save_state(state_path, state)
    gating = load_gating()
    plan = (pol.get('plans') or {}).get(args.plan) or []
    if not plan:
        print('unknown plan:', args.plan)
        return 2
    budget = pol.get('budget') or {}
    max_plugins = int(budget.get('max_plugins', 20))
    max_seconds = float(budget.get('max_seconds', 1800))
    min_interval = float((pol.get('rate_limit') or {}).get('min_interval_seconds', 0.2))
    read_only = bool(pol.get('read_only', False))
    resume = bool((pol.get('state') or {}).get('resume', True))
    abort_file = os.path.join(ROOT, pol.get('abort_file', 'state/ABORT'))
    run = {'plan': args.plan, 'started_at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'policy': {'max_plugins': max_plugins, 'max_seconds': max_seconds, 'min_interval': min_interval, 'read_only': read_only, 'resume': resume}, 'steps': [], 'verdict': 'UNKNOWN'}
    t0 = time.time()
    executed = 0
    for name in plan:
        step = {'name': name}
        if executed >= max_plugins:
            step.update({'skipped': 'budget_max_plugins'})
            run['steps'].append(step)
            break
        if time.time() - t0 > max_seconds:
            step.update({'skipped': 'budget_max_seconds'})
            run['steps'].append(step)
            break
        if os.path.exists(abort_file):
            step.update({'skipped': 'abort_file'})
            run['steps'].append(step)
            break
        if name not in PLUGINS:
            step.update({'skipped': 'unknown_plugin'})
            run['steps'].append(step)
            continue
        meta = PLUGINS[name]
        (cmd, is_write, desc, expected_fail) = (meta['cmd'], meta['write'], meta['desc'], meta['expected_fail'])
        rule = meta.get('rule')
        if rule and gating.get(rule) is False:
            step.update({'skipped': 'gated_off:%s' % rule})
            run['steps'].append(step)
            continue
        if read_only and is_write:
            step.update({'skipped': 'read_only_policy'})
            run['steps'].append(step)
            continue
        if resume and name in (state.get('completed') or {}):
            step.update({'skipped': 'already_completed', 'previous': state['completed'][name]})
            run['steps'].append(step)
            continue
        ts = time.time()
        plugin = CliPlugin(name, cmd, write=is_write, description=desc)
        pr = plugin.run()
        rc = pr.detail.get('returncode', 1)
        ok = rc == 0 if not expected_fail else rc != 0
        step.update({'returncode': rc, 'expected_fail': expected_fail, 'ok': ok, 'elapsed': round(time.time() - ts, 1), 'stdout_tail': (pr.detail.get('stdout_tail') or '')[-600:], 'stderr_tail': (pr.detail.get('stderr_tail') or '')[-300:], 'write': is_write, 'description': desc})
        run['steps'].append(step)
        executed += 1
        state.setdefault('completed', {})[name] = {'returncode': rc, 'finished_at': time.strftime('%Y-%m-%dT%H:%M:%S')}
        save_state(state_path, state)
        print('PASS' if ok else 'FAIL', name, 'rc=', rc, 'expected_fail=', expected_fail, round(step['elapsed'], 1), 's')
        time.sleep(min_interval)
    ran = [s for s in run['steps'] if 'returncode' in s]
    fails = [s['name'] for s in ran if not s.get('ok')]
    known = [s['name'] for s in ran if s.get('expected_fail')]
    run['ran'] = len(ran)
    run['failed'] = fails
    run['known_issues'] = known
    run['verdict'] = 'PASS' if ran and (not fails) else 'PASS_WITH_KNOWN_ISSUES' if fails and len(fails) == len(known) else 'FAIL'
    run['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
    state.setdefault('runs', []).append({'plan': args.plan, 'verdict': run['verdict'], 'finished_at': run['finished_at']})
    save_state(state_path, state)
    json.dump(run, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('verdict:', run['verdict'], 'ran:', run['ran'], 'failed:', fails)
    return 0 if run['verdict'] == 'PASS' else 1
if __name__ == '__main__':
    sys.exit(main())
