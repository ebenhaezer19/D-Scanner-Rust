# benchmark_wp2shell.ps1
# Compare Rust vs Python wp2shell scan speed on the same host list.
# Usage: .\benchmark_wp2shell.ps1

$hosts_file = "test_wp2shell_hosts.txt"
$rust_bin   = ".\target\release\dreks.exe"

Write-Host "=== wp2shell speed benchmark ===" -ForegroundColor Cyan

# ── Build Rust release binary ──────────────────────────────────────────────
Write-Host "`n[1/3] Building Rust release binary ..." -ForegroundColor Yellow
$build = Measure-Command { cargo build --release 2>&1 | Out-Null }
Write-Host ("    build time: {0:F2}s" -f $build.TotalSeconds)

# ── Rust scan ─────────────────────────────────────────────────────────────
Write-Host "`n[2/3] Running Rust wp2shell scan ..." -ForegroundColor Yellow
$rust_time = Measure-Command {
    & $rust_bin wp2shell -f $hosts_file -j | Out-Null
}
Write-Host ("    Rust elapsed: {0:F3}s" -f $rust_time.TotalSeconds)

# ── Python scan ────────────────────────────────────────────────────────────
Write-Host "`n[3/3] Running Python wp2shell scan ..." -ForegroundColor Yellow
# Download wp2shell.py if not present
if (-not (Test-Path "wp2shell.py")) {
    Write-Host "    (downloading wp2shell.py ...)"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ZephrFish/wp2shell-scanner/refs/heads/main/wp2shell.py" -OutFile "wp2shell.py"
}
$py_time = Measure-Command {
    python wp2shell.py --scan --file $hosts_file --threads 10 2>&1 | Out-Null
}
Write-Host ("    Python elapsed: {0:F3}s" -f $py_time.TotalSeconds)

# ── Summary ────────────────────────────────────────────────────────────────
Write-Host "`n=== RESULT ===" -ForegroundColor Cyan
$speedup = $py_time.TotalSeconds / $rust_time.TotalSeconds
Write-Host ("    Python : {0:F3}s" -f $py_time.TotalSeconds)
Write-Host ("    Rust   : {0:F3}s" -f $rust_time.TotalSeconds)
Write-Host ("    Speedup: {0:F1}x faster" -f $speedup) -ForegroundColor Green
