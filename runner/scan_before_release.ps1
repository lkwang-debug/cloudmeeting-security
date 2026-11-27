# 版本放行前扫描（报告模式，不阻断发版）
# 用法： powershell -ExecutionPolicy Bypass -File runner\scan_before_release.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$logDir = Join-Path $root "reports\final\ci_logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir ("release-scan-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
$py = Join-Path $root ".venv\Scripts\python.exe"
& $py (Join-Path $root "runner\refresh_web_tokens.py") *>&1 | Tee-Object -FilePath $log -Append
& $py (Join-Path $root "runner\preflight.py") *>&1 | Tee-Object -FilePath $log -Append
& $py (Join-Path $root "runner\release_gate.py") --profile release *>&1 | Tee-Object -FilePath $log -Append
# 报告模式：不阻断发版，退出码始终 0；结论见 gate_result.json / RELEASE_GATE.md
"RELEASE SCAN finished at $(Get-Date -Format o), report-only, log=$log" | Tee-Object -FilePath $log -Append
exit 0
