# 版本放行前扫描（报告模式，不阻断）
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$logDir = Join-Path $root "reports\final\ci_logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir ("release-scan-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
$py = Join-Path $root ".venv\Scripts\python.exe"
& $py (Join-Path $root "runner\preflight.py") *>&1 | Tee-Object -FilePath $log
& $py (Join-Path $root "runner\release_gate.py") --profile release *>&1 | Tee-Object -FilePath $log -Append
"RELEASE SCAN finished at $(Get-Date -Format o), report-only, log=$log" | Tee-Object -FilePath $log -Append
exit 0
