# 一键扫描：读取 configs/scan.local.yaml -> 预检 -> preflight -> release gate
# 用法：powershell -ExecutionPolicy Bypass -File runner\run_scan.ps1 -Profile release
param(
  [ValidateSet("quick","release")] [string]$Profile = "release",
  [switch]$CheckOnly,
  [switch]$SkipCheck
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$py = Join-Path $root ".venv\Scripts\python.exe"
$args = @((Join-Path $root "runner\run_scan.py"), "--profile", $Profile)
if ($CheckOnly) { $args += "--check-only" }
if ($SkipCheck) { $args += "--skip-check" }
& $py @args
exit $LASTEXITCODE
