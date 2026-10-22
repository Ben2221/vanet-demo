"""Non-overwriting result storage for the dense presentation demo.

Keep each run's standard scenario outputs together, and use the existing
collector for the same per-run numbers as experiments/run.py.
"""

from __future__ import annotations

import csv
import json
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
import sys
import traceback

from experiments.collect import collect_run

RESULTS = Path(__file__).resolve().parent / "results" / "dense_presentation_250"


def write_json(path: Path, value: dict) -> None:
    """Replace metadata atomically so a stopped process cannot leave half a JSON file."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")
    temporary.replace(path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def set_status(out: Path, state: str, **details) -> None:
    path = out / "run_status.json"
    status = json.loads(path.read_text()) if path.exists() else {"schema_version": 1}
    status.update(state=state, updated_at_utc=_now(), **details)
    write_json(path, status)


def save_completed(out: Path, *, reference: bool = False) -> None:
    """Index only real completed outputs; never infer a missing simulation summary."""
    config = json.loads((out / "config.json").read_text())
    summary = json.loads((out / "summary.json").read_text())
    if float(config["duration"]) != float(summary["duration_s"]):
        raise ValueError(f"Configuration and summary duration do not match in {out}")
    if not (out / "metrics.csv").is_file() or not (out / "protocol_stats.json").is_file():
        raise ValueError(f"Completed scenario outputs are missing in {out}")
    collected = collect_run(out)
    write_json(out / "results.json", collected)
    run = out.relative_to(RESULTS).as_posix()
    row = {"run": run, "status": "completed", "reference": reference,
           "vehicles": summary["vehicles"], "rsus": summary["rsus"],
           "duration": summary["duration_s"], "seed": config["seed"],
           "backend": config["backend"], "protocol": config["protocol"],
           "profile": config["profile"], "attack": config["attack"],
           "attack_start": config["attack_start"], **collected}
    index = RESULTS / "runs.csv"
    if index.exists():
        with index.open(newline="", encoding="utf-8") as f:
            rows = [old for old in csv.DictReader(f) if old["run"] != run]
    else:
        rows = []
    rows.append(row)
    columns = sorted({key for item in rows for key in item}, key=lambda key: (key == "run", key))
    temporary = index.with_suffix(".csv.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(index)
    set_status(out, "completed", completed_at_utc=_now(), duration_s=summary["duration_s"],
               reference=reference)
    pointer = {"schema_version": 1, "run": run, "state": "completed",
               "duration_s": summary["duration_s"], "vehicles": summary["vehicles"],
               "updated_at_utc": _now()}
    if reference:
        pointer["note"] = "Existing completed development result, not a full 30-second presentation run."
        write_json(RESULTS / "reference.json", pointer)
    if not reference or not (RESULTS / "latest.json").exists():
        write_json(RESULTS / "latest.json", pointer)


def register_reference() -> bool:
    """Leave the legacy flat run in place and register it once if it is complete."""
    if (RESULTS / "reference.json").exists():
        return True
    required = ("config.json", "summary.json", "metrics.csv", "protocol_stats.json")
    if not all((RESULTS / filename).is_file() for filename in required):
        return False
    save_completed(RESULTS, reference=True)
    return True


class _Tee:
    def __init__(self, console, log):
        self.console = console
        self.log = log

    def __getattr__(self, name):
        return getattr(self.console, name)

    def write(self, text):
        self.console.write(text)
        self.log.write(text)
        self.log.flush()
        return len(text)

    def flush(self):
        self.console.flush()
        self.log.flush()


@contextmanager
def stored_run(parameters: dict):
    """Preserve old runs and retain logs/status even when a run fails or is interrupted."""
    RESULTS.mkdir(parents=True, exist_ok=True)
    register_reference()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    name = f"{timestamp}_v250_d{parameters['duration']:g}_s{parameters['seed']}"
    out = RESULTS / "runs" / name
    out.mkdir(parents=True, exist_ok=False)
    set_status(out, "running", started_at_utc=_now(), parameters=parameters)
    with (out / "run.log").open("w", encoding="utf-8", buffering=1) as log:
        with redirect_stdout(_Tee(sys.stdout, log)), redirect_stderr(_Tee(sys.stderr, log)):
            print(f"Storing this run in: {out}", flush=True)
            try:
                yield out
            except BaseException as exc:
                status = json.loads((out / "run_status.json").read_text())
                if status["state"] not in {"completed", "built"}:
                    set_status(out, "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
                               error=f"{type(exc).__name__}: {exc}")
                traceback.print_exc()
                raise
