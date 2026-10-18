"""Baseline authentication schemes for the comparison (Person 4).

Both run in the same scenario as ours (same radio, same mobility, same attackers,
same detector and metrics), by reusing the message flow of the stand-in protocol
(network/protocols/stub_auth.py) and changing only what the scheme changes:

ecdsa_pki     Each pseudonym carries an ECDSA certificate from the CA. The RSU verifies
              the certificate chain and the request signature (2 ECDSA verifies), checks
              its local copy of the revocation list, and keeps no shared state: every
              handover is a full check again. No ledger writes for authorizations.

central_auth  The RSU asks a central authority about every authentication and every
              handover (a backbone round trip plus the authority's own verification).
              Always correct and always fresh, but every request waits for the round trip.

What is modelled, and what is not (say so in the report):
 * sizes and compute times of the requests and responses, the extra round trip
 * not modelled: backbone queueing at the central authority, certificate expiry
 * the handover request has the same wire size as in our scheme (the stand-in builds it
   internally); the difference between schemes there is the check cost and the round trip
 * ECDSA times come from experiments/measure_ecdsa.py (pass --compute-times); if the
   file has no "ecdsa_*" entries the scheme runs with zero crypto delay and says so.
Central authority numbers: --config ca_rtt_ms / ca_proc_ms are read from the scenario
config when present (defaults: 20 ms backbone round trip, 1 ms processing).
"""

from __future__ import annotations

from network.protocols import stub_auth as S

ECDSA_SIG = 64
ECDSA_CERT = 130            # an IEEE 1609.2 pseudonym certificate is about this size
CERT_DIGEST = 8             # BSMs carry the certificate digest; the full certificate goes with AUTH_REQ


class _Vehicle(S.Vehicle):
    def make_bsm(self, node, sim_time: float, state: dict) -> bytes:
        body = S.PLAIN_BSM.pack(S.BSM, self.pid, state["seq"], sim_time, state["x"], state["y"],
                                state["speed"], state["heading"])
        return S._pad(body, ECDSA_SIG + CERT_DIGEST)

    def _send_auth(self, node, rsu: int, nonce: bytes, sim_time: float) -> None:
        req = S._AUTH_REQ.pack(S.AUTH_REQ, self.pid, rsu, nonce, sim_time, 1, 1)
        self.pending = (rsu, sim_time, "auth")
        node.send(node.last_sender, S._pad(req, ECDSA_SIG + ECDSA_CERT),
                  delay=node.processing_delay("ecdsa_sign"))


class _Rsu(S.Rsu):
    record_authorization = False          # ecdsa_pki: nothing is shared between RSUs
    central = False

    def _check_cost(self, node, kind: str) -> float:
        cost = 2 * node.processing_delay("ecdsa_verify")        # certificate + signature
        if self.central:
            cfg = node.env.config
            cost += (cfg.get("ca_rtt_ms", 20.0) + cfg.get("ca_proc_ms", 1.0)) / 1000.0
        return cost

    def _auth(self, node, data: bytes, sim_time: float) -> None:
        _, pid, rsu, nonce, t_req, _, _ = S._AUTH_REQ.unpack_from(data)
        if rsu != self.index:
            return
        pid_hex = pid.hex()
        cost = self._check_cost(node, "auth")
        reason = None
        if not self._fresh(nonce) or (pid, nonce) in self.used:
            reason = "stale_or_replayed_nonce"
        elif pid_hex not in node.env.shared["registered"]:
            reason = "unregistered"
        elif node.ledger.is_revoked(pid_hex):          # the revocation list / the CA's answer
            reason = "revoked"
        self.used.add((pid, nonce))
        if reason:
            node.log("AUTH_REJECT", len(data), None, f"{pid_hex}:{reason}")
            self._reply(node, node.last_sender, pid, False, False, t_req, cost)
            return
        node.log("AUTH_VERIFY", len(data), cost * 1000, pid_hex)
        self._reply(node, node.last_sender, pid, True, False, t_req, cost + node.processing_delay("ecdsa_sign"))

    def _handover(self, node, data: bytes, sim_time: float) -> None:
        _, pid, rsu, nonce, t_req = S._HO_REQ.unpack_from(data)
        if rsu != self.index:
            return
        pid_hex = pid.hex()
        ok = (self._fresh(nonce) and pid_hex in node.env.shared["registered"]
              and not node.ledger.is_revoked(pid_hex))
        cost = self._check_cost(node, "handover")           # no shared record: a full check again
        node.log("HANDOVER_CHECK", len(data), None, f"{pid_hex}:{'ok' if ok else 'rejected'}")
        self._reply(node, node.last_sender, pid, ok, True, t_req, cost + node.processing_delay("ecdsa_sign"))


class EcdsaRsu(_Rsu):
    pass


class CentralRsu(_Rsu):
    central = True


def make(rsu_class):
    """Module-level hooks (interface 3) for one scheme."""
    return {
        "setup": S.setup,
        "message_type": S.message_type,
        "create_vehicle": lambda node, env: _Vehicle(node, env),
        "create_rsu": lambda node, env: rsu_class(node, env),
    }
