# Live demo: three vehicles, two RSUs, 30 seconds

This standalone demo reuses the project's existing browser UI, real protocol,
ns-3 radio backend and SUMO/TraCI mobility. No original simulation files are changed.

## Windows + WSL: launch

From PowerShell in the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\network\start_visibility_demo.ps1
```

The launcher uses **Ubuntu**, opens **http://localhost:8765** in your Windows
browser and runs **30 simulated seconds at 1x speed**. Startup includes ns-3
compilation, so the window takes a little time to appear. The final state stays
available until you press **Ctrl+C** in the terminal. Run the command again to replay.

The WSL Python environment is separate from your Windows `.venv`:
`~/.local/share/vanet-demo-venv`. It contains ns-3 3.44, SUMO, NumPy, coincurve,
cryptography and defusedxml.

## Inside Ubuntu / WSL

From this repository's directory:

```sh
~/.local/share/vanet-demo-venv/bin/python network/visibility_demo.py \
  --backend ns3 --duration 30 --viz --open-browser
```

- **3 vehicles** start together, 70 m apart, and drive along a 900 m road.
  Speed is set to 24 m/s for the 30-second run, keeping all three on the road.
- **2 RSUs** sit at 225 m and 675 m along the road, 20 m to the side, with
  300 m nominal service ranges.
- SUMO is stepped through **TraCI every 0.1 s**; its positions and velocities
  drive ns-3 live. The browser displays this simulation, not a separate animation.
- The existing **v3-fast real protocol** is used with RSU CPU modelling, V2V
  verification and privacy logging. RSU clustering is disabled only in this demo
  so moving to the other RSU can demonstrate handover.
- The ledger is the built-in mock; a Fabric network is not needed.

Click a vehicle or RSU to inspect its state and recent events. The existing UI
also provides pause and speed controls. No attackers or emergency vehicles are
added to this visibility demo.

Outputs, including `config.json`, `metrics.csv`, `summary.json`, `protocol_stats.json`,
`netanim.xml`, `flowmon.xml` and the SUMO files, are written under
`experiments/results/visibility_3v2r/`. Use `--out PATH` to choose another directory.

For a bounded run that closes the UI server 15 seconds after completion:

```sh
~/.local/share/vanet-demo-venv/bin/python network/visibility_demo.py \
  --backend ns3 --duration 30 --viz --open-browser --hold-seconds 15
```

`--build-only` prepares just the SUMO scenario. `--mobility trace` uses the exported
SUMO trace instead of live TraCI. `--backend lite` is available for development,
but the Windows launcher explicitly selects ns-3 and never silently substitutes it.
