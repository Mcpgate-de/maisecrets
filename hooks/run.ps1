# Hook launcher for Windows without Git Bash. Codex runs it through `commandWindows` in
# hooks/hooks.json; Claude Code on Windows keeps run.sh (it requires Git Bash).
# Same job as run.sh: find a Python 3.11+, run dispatch.py with the event, hand the payload
# on stdin through byte for byte. The payload is copied as raw bytes on purpose: PowerShell's
# own text pipe re-encodes with the console code page and damages a prompt with umlauts.
# Fails closed: without Python the launcher exits 2 (a block in Claude Code; Codex runs the
# tool anyway on a failed hook, so the message names the missing piece).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File run.ps1 <event> [args]
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dispatch = Join-Path $here "dispatch.py"

function Quote([string]$s) { '"' + ($s -replace '(\\*)"', '$1$1\"') + '"' }

$candidates = @(
    @{ exe = "py"; pre = @("-3") },
    @{ exe = "python"; pre = @() },
    @{ exe = "python3"; pre = @() }
)
foreach ($c in $candidates) {
    $cmd = Get-Command $c.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    $exe = $cmd.Source
    if (-not $exe) { continue }
    try {
        $probe = New-Object System.Diagnostics.ProcessStartInfo
        $probe.FileName = $exe
        $probe.Arguments = (($c.pre + @("-c", "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)")) | ForEach-Object { Quote $_ }) -join " "
        $probe.UseShellExecute = $false
        $probe.RedirectStandardOutput = $true
        $probe.RedirectStandardError = $true
        $pp = [System.Diagnostics.Process]::Start($probe)
        $pp.WaitForExit()
        if ($pp.ExitCode -ne 0) { continue }
    } catch { continue }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = (($c.pre + @($dispatch) + $args) | ForEach-Object { Quote $_ }) -join " "
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    # stdout and stderr stay inherited: the hook's JSON answer goes straight to the client
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdin = [Console]::OpenStandardInput()
        $stdin.CopyTo($p.StandardInput.BaseStream)
        $p.StandardInput.BaseStream.Flush()
    } catch {
        # a launcher started without a payload (no stdin) still runs the command
    } finally {
        $p.StandardInput.Close()
    }
    $p.WaitForExit()
    exit $p.ExitCode
}
[Console]::Error.WriteLine("maisecrets: no Python 3.11+ found (tried py -3, python, python3); prompt blocked")
exit 2
