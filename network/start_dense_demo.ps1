param(
    [ValidateRange(11, 3600)]
    [int]$Duration = 30,
    [ValidateRange(1024, 65535)]
    [int]$Port = 8766,
    [double]$HoldSeconds = -1
)

$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$command = "exec ~/.local/share/vanet-demo-venv/bin/python -u network/dense_demo.py --duration $Duration --viz-port $Port --open-browser"
if ($HoldSeconds -ge 0) {
    $command += " --hold-seconds $HoldSeconds"
}

# Ubuntu owns the ns-3 environment; leave the Windows .venv untouched.
wsl.exe -d Ubuntu --cd $project -- bash -lc $command
exit $LASTEXITCODE
