"""V8 检查插件生命周期接口（准备/执行/验证/清理）。
现有脚本可通过 CLI 适配器接入编排层；新插件建议直接继承 Plugin。
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
from dataclasses import dataclass, field
from typing import Any, Dict

@dataclass
class PluginResult:
    ok: bool
    detail: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ''

class Plugin:
    name = 'base'
    write = False
    description = ''

    def prepare(self) -> None:
        """准备阶段：校验 token/环境/前置数据"""
        pass

    def execute(self) -> PluginResult:
        raise NotImplementedError

    def verify(self) -> PluginResult:
        """验证阶段：正例/负例/状态反查"""
        return PluginResult(ok=True)

    def cleanup(self) -> None:
        """清理阶段：删除测试数据/缓存"""
        pass

    def run(self) -> PluginResult:
        self.prepare()
        try:
            result = self.execute()
            if result.ok:
                v = self.verify()
                if not v.ok:
                    result.ok = False
                    result.detail['verify'] = v.detail
            return result
        finally:
            self.cleanup()

class CliPlugin(Plugin):
    """把现有 CLI 脚本适配为插件（与编排层 subprocess 方式一致）。"""

    def __init__(self, name, command, write=False, description=''):
        self.name = name
        self.command = command
        self.write = write
        self.description = description

    def execute(self):
        import os
        import subprocess
        ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p = subprocess.run(self.command, cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1800)
        return PluginResult(ok=p.returncode == 0, detail={'returncode': p.returncode, 'stdout_tail': (p.stdout or '')[-600:], 'stderr_tail': (p.stderr or '')[-300:]})
