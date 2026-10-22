$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot

# Use Ubuntu explicitly: docker-desktop may be the default WSL distribution.
wsl.exe -d Ubuntu --cd $project -- bash -lc 'exec ~/.local/share/vanet-demo-venv/bin/python -u network/visibility_demo.py --backend ns3 --duration 30 --viz --open-browser'
exit $LASTEXITCODE
