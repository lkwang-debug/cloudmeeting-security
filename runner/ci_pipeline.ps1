# CI 流水线（Windows）: 运行 runner/run_all.py，记录日志并按退出码返回
# 手动： powershell -ExecutionPolicy Bypass -File runner\ci_pipeline.ps1
# 注册每日 02:00（管理员/当前用户）：
#   schtasks /Create /TN "CloudMeetingSec-CI" /SC DAILY /ST 02:00 /TR "powershell -ExecutionPolicy Bypass -File configured-path" /F
# 删除： schtasks /Delete /TN "CloudMeetingSec-CI" /F
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$logDir = Join-Path $root "reports\final\ci_logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$log = Join-Path $logDir "ci-$ts.log"
$py = Join-Path $root ".venv\Scripts\python.exe"
& $py (Join-Path $root "runner\run_all.py") *>&1 | Tee-Object -FilePath $log
$code = $LASTEXITCODE
# 夜间基线：门禁结果归档，不阻断（产品修复前允许 FAIL/BLOCKED）
& $py (Join-Path $root "runner\release_gate.py") --profile quick *>&1 | Tee-Object -FilePath $log -Append
$gateCode = $LASTEXITCODE
"GATE finished at $(Get-Date -Format o), gate_exit=$gateCode, log=$log" | Tee-Object -FilePath $log -Append
"CI finished at $(Get-Date -Format o), exit=$code, log=$log" | Tee-Object -FilePath $log -Append
exit $code
