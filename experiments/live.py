"""Narrate a run in plain English, live while ns-3 runs or replayed from a finished run.

    make live                                         # run v3-fast on ns-3 and narrate it
    python experiments/live.py experiments/results/demo/v3-fast [--speed 4] [--all]

Reads the same events as metrics.csv. The first time each kind of event appears it adds a
one-line explanation; every 5 simulated seconds it prints a status line. --all prints every
handover, renewal and ledger write too.
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

TTY = sys.stdout.isatty()


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if TTY else s


GREEN, RED, YELLOW, CYAN, DIM, BOLD = (lambda s: _c("32", s), lambda s: _c("31", s), lambda s: _c("33", s),
                                       lambda s: _c("36", s), lambda s: _c("2", s), lambda s: _c("1", s))

EXPLAIN = {
    "AUTH_OK": "the car proved it is a registered vehicle without revealing which one (zero-knowledge "
               "proof); the roadside unit (RSU) gave it a short-lived ticket to sign its messages with",
    "HANDOVER_OK": "the car drove into the next RSU's range and showed its ticket instead of proving again",
    "RENEW_OK": "the ticket was about to expire, so the car swapped it for a fresh one",
    "ATTACK_START": "from now on this car broadcasts false positions (ground truth, the RSUs do not know it)",
    "DETECT_FLAG": "the RSU's misbehaviour detector saw a physically impossible position or speed",
    "FALSE_FLAG": "one RSU's detector misjudged an honest car; one flag alone does nothing: revocation needs "
                  "reports from 2 RSUs, so this costs the car nothing",
    "SPARE_REVOKED": "once the identity is known, the car's unused pseudonyms are revoked too, so it cannot "
                     "simply switch to a fresh one",
    "REPORT": "the RSU reported the pseudonym to the blockchain (Hyperledger Fabric ledger)",
    "QUARANTINE_SENT": "the RSU told nearby RSUs to ignore this pseudonym right away, before the ledger commits",
    "REVOKED_VISIBLE": "enough RSUs reported it, the ledger revoked the pseudonym and every RSU now sees that",
    "IDENTITY_REVEALED": "a threshold of RSUs jointly decrypted which real vehicle was behind the pseudonym "
                         "(no single party can do this alone)",
    "AUTH_REJECTED": "the attacker tried again with a new pseudonym, but its credential is revoked",
    "ALL_PSEUDONYMS_REVOKED": "the attacker has no usable pseudonym left: it is shut out of the network",
    "PSEUDONYM_CHANGE": "the car switched to a new random ID so an eavesdropper cannot follow it",
    "TRUST_UPDATE": "RSUs whose reports were confirmed gain weight in future revocation votes",
}

QUIET_AFTER = 15     # after this many joins / false flags, only the status line counts them

SHOW = {"AUTH_OK", "ATTACK_START", "DETECT_FLAG", "QUARANTINE_SENT", "REVOKED_VISIBLE", "IDENTITY_REVEALED",
        "AUTH_REJECTED", "ALL_PSEUDONYMS_REVOKED", "LEAVE"}
SHOW_ALL = SHOW | {"HANDOVER_OK", "HANDOVER_FALLBACK", "RENEW_OK", "REPORT", "PSEUDONYM_CHANGE", "TRUST_UPDATE",
                   "BSM_REJECT", "LEDGER_VISIBLE", "CLUSTER_SWITCH"}


class Narrator:
    def __init__(self, show_all: bool = False, every: float = 5.0, counters=None, out=sys.stdout,
                 pace: float = 0.0) -> None:
        self.show = SHOW_ALL if show_all else SHOW
        self.every = every
        self.counters = counters      # live mode: () -> {"BSMs sent": n, ...} from the simulator
        self.out = out
        self.next_status = every
        self.explained: set[str] = set()
        self.owner: dict[str, str] = {}           # pseudonym -> vehicle
        self.attackers: set[str] = set()
        self.on_road: set[str] = set()
        self.joined: set[str] = set()
        self.flagged: set[str] = set()            # pseudonyms flagged
        self.caught: set[str] = set()             # attacker vehicles with a revoked pseudonym
        self.false_flags: set[str] = set()        # honest vehicles flagged by a single RSU
        self.false_alarms: set[str] = set()       # honest vehicles that lost a pseudonym
        self.spare = 0                            # revoked pseudonyms never used on air, not yet printed
        self.spare_t = 0.0
        self.revoked: set[str] = set()
        self.n = {"handovers": 0, "renewals": 0, "rejected BSMs": 0}
        self.cbr: dict[str, float] = {}
        self.t = 0.0
        self.pace = pace              # simulated s per wall s, 0 = no waiting
        self.wall0 = None

    def _p(self, s: str = "") -> None:
        print(s, file=self.out, flush=True)

    def _who(self, pid: str) -> str:
        veh = self.owner.get(pid)
        if veh is None:
            return pid[:8]
        tag = RED(" (attacker)") if veh in self.attackers else GREEN(" (honest)")
        return f"{pid[:8]}={veh}{tag}"

    def _say(self, t: float, node: str, text: str, event: str) -> None:
        self._flush_spare()
        self._p(f"{DIM(f'[{t:6.2f}s]')} {node:<7} {text}")
        if event in EXPLAIN and event not in self.explained:
            self.explained.add(event)
            self._p(DIM(f"           └─ {EXPLAIN[event]}"))

    def _flush_spare(self) -> None:
        if self.spare:
            n, self.spare = self.spare, 0
            self._say(self.spare_t, "ledger", BOLD(f"⛓ {n} spare pseudonyms of the revealed attackers REVOKED"),
                      "SPARE_REVOKED")

    def status(self, t: float) -> None:
        self._flush_spare()
        cbr = sum(self.cbr.values()) / len(self.cbr) if self.cbr else 0.0
        caught = f"{len(self.caught)}/{len(self.attackers)}" if self.attackers else "0 (no attack yet)"
        extra = "".join(f" | {k} {v:,}" for k, v in (self.counters() if self.counters else {}).items())
        self._p(CYAN(f"── t={t:5.1f}s | cars on road {len(self.on_road)} | authenticated {len(self.joined)} | "
                     f"handovers {self.n['handovers']} | renewals {self.n['renewals']} | channel busy "
                     f"{cbr:.1%} | attackers caught {caught} | false flags {len(self.false_flags)} | "
                     f"honest revoked {len(self.false_alarms)}{extra} ──"))

    def feed(self, t: float, node: str, event: str, nbytes, latency, result: str) -> None:
        t = float(t)
        if self.pace > 0:
            # hold the simulator back so simulated time runs at `pace` x wall-clock time
            self.wall0 = self.wall0 if self.wall0 is not None else time.time() - t / self.pace
            wait = self.wall0 + t / self.pace - time.time()
            if wait > 0:
                time.sleep(wait)
        while t >= self.next_status:
            self.status(self.next_status)
            self.next_status += self.every
        self.t = t
        lat = f" in {float(latency):.2f} ms" if latency not in (None, "") else ""
        if event == "ENTER":
            self.on_road.add(node)
        elif event == "LEAVE":
            self.on_road.discard(node)
        elif event == "PID_ASSIGN":
            self.owner[result] = node
        elif event == "PSEUDONYM_CHANGE" and "->" in result:
            self.owner[result.split("->")[-1].strip()] = node
        elif event == "CBR":
            self.cbr[node] = float(result)
        elif event in ("HANDOVER_OK", "HANDOVER_FALLBACK"):
            self.n["handovers"] += 1
        elif event == "RENEW_OK":
            self.n["renewals"] += 1
        elif event == "BSM_REJECT":
            self.n["rejected BSMs"] += 1
        elif event == "ATTACK_START":
            self.attackers.add(node)

        if event not in self.show:
            return
        if event == "AUTH_OK":
            first = node not in self.joined
            self.joined.add(node)
            if self.show is SHOW and (not first or len(self.joined) > QUIET_AFTER):
                if len(self.joined) == QUIET_AFTER + 1 and first:
                    self._p(DIM(f"           (more than {QUIET_AFTER} cars: further joins are counted in the status line)"))
                return
            self._say(t, node, f"{GREEN('✓ joined')} via {result}: anonymous ticket issued{lat}", event)
        elif event == "LEAVE":
            if len(self.joined) <= QUIET_AFTER or self.show is not SHOW:
                self._say(t, node, DIM("left the map"), event)
        elif event == "ATTACK_START":
            self._say(t, node, RED(f"⚠ ATTACK STARTS ({result})"), event)
        elif event == "DETECT_FLAG":
            if result in self.flagged:
                return
            self.flagged.add(result)
            veh = self.owner.get(result)
            if veh and veh not in self.attackers:
                self.false_flags.add(veh)
                if self.show is SHOW and len(self.false_flags) > QUIET_AFTER:
                    if len(self.false_flags) == QUIET_AFTER + 1:
                        self._p(DIM(f"           (further single false flags are counted in the status line)"))
                    return
                self._say(t, node, YELLOW(f"? flagged {self._who(result)}: a single report, no action"),
                          "FALSE_FLAG")
            else:
                self._say(t, node, YELLOW(f"🚩 flagged {self._who(result)}"), event)
        elif event == "REPORT":
            self._say(t, node, f"reported {self._who(result)} to the ledger", event)
        elif event == "QUARANTINE_SENT":
            pid, n = (result.split(":") + ["?"])[:2]
            self._say(t, node, YELLOW(f"quarantine: told {n} neighbouring RSUs to drop {self._who(pid)}"), event)
        elif event == "REVOKED_VISIBLE":
            self.revoked.add(result)
            veh = self.owner.get(result)
            if veh is None:
                self.spare, self.spare_t = self.spare + 1, t
                return
            if veh in self.attackers:
                self.caught.add(veh)
            else:
                self.false_alarms.add(veh)
            self._say(t, "ledger", BOLD(f"⛓ block committed: {self._who(result)} REVOKED"), event)
        elif event == "IDENTITY_REVEALED":
            self._say(t, node, f"identity revealed: {result}", event)
        elif event == "AUTH_REJECTED":
            self._say(t, node, RED(f"✗ rejected by {result.replace(':', ' (')})"), event)
        elif event == "ALL_PSEUDONYMS_REVOKED":
            self._say(t, node, BOLD(RED("■ shut out: every pseudonym revoked")), event)
        elif event == "HANDOVER_OK":
            self._say(t, node, f"handover to {result}{lat}", event)
        elif event == "HANDOVER_FALLBACK":
            self._say(t, node, f"handover to {result} failed, full authentication instead", event)
        elif event == "RENEW_OK":
            self._say(t, node, f"ticket renewed at {result}{lat}", event)
        elif event == "PSEUDONYM_CHANGE":
            self._say(t, node, f"pseudonym change ({result})", event)
        elif event == "TRUST_UPDATE":
            self._say(t, node, f"trust weight {result}", event)
        elif event == "BSM_REJECT":
            self._say(t, node, f"dropped a BSM from {self._who(result.split(':')[0])}", event)
        elif event == "LEDGER_VISIBLE":
            self._say(t, node, f"ledger write committed: {result}{lat}", event)
        elif event == "CLUSTER_SWITCH":
            self._say(t, node, f"entered RSU cluster of {result}", event)

    def finish(self) -> None:
        self.status(self.t)
        honest = [v for v in self.false_alarms]
        self._p()
        self._p(BOLD("Result"))
        self._p(f"  cars authenticated      {len(self.joined)}")
        self._p(f"  handovers / renewals    {self.n['handovers']} / {self.n['renewals']}")
        self._p(f"  attackers               {len(self.attackers)}, caught {len(self.caught)}"
                + (GREEN("  ✓ all caught") if self.attackers and self.caught >= self.attackers else ""))
        self._p(f"  honest cars flagged     {len(self.false_flags)} (single reports, no action taken)")
        self._p(f"  honest cars revoked     {len(honest)}" + (GREEN("  ✓ no false alarms") if not honest else
                                                              RED("  " + ", ".join(sorted(honest)))))
        self._p(f"  BSMs dropped at RSUs    {self.n['rejected BSMs']} (from quarantined or revoked senders)")


def replay(run: Path, speed: float, show_all: bool) -> None:
    nar = Narrator(show_all)
    cfg = run / "config.json"
    if cfg.exists():
        import json
        c = json.loads(cfg.read_text())
        print(BOLD(f"Replaying {run}: {c.get('profile') or 'Phase-I'} profile, {c.get('vehicles_in_trace') or c.get('vehicles')} vehicles, "
                   f"{c.get('duration')} s, {c.get('backend')} backend, attack {c.get('attack')} "
                   f"from {c.get('attack_start')} s ({speed:g}x speed)"))
    start, t0 = time.time(), None
    with (run / "metrics.csv").open(newline="") as f:
        for r in csv.DictReader(f):
            t = float(r["sim_time"])
            if speed > 0:
                t0 = t if t0 is None else t0
                wait = (t - t0) / speed - (time.time() - start)
                if wait > 0:
                    time.sleep(wait)
            nar.feed(t, r["node"], r["event"], r["bytes"], r["latency_ms"], r["result"])
    nar.finish()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run", type=Path, help="a finished run folder (has metrics.csv)")
    ap.add_argument("--speed", type=float, default=4.0, help="simulated seconds per wall second (0 = no pause)")
    ap.add_argument("--all", action="store_true", help="also every handover, renewal and ledger write")
    a = ap.parse_args()
    try:
        replay(a.run, a.speed, a.all)
    except KeyboardInterrupt:
        pass
