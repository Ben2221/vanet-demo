"""VANET Cryptography and Authentication Protocol Package.

Module-level node hooks for the simulator (docs/interfaces.md, section 3):
create_vehicle, create_rsu, setup and message_type. They live in sim_app,
which imports the network package, so it is loaded only when the simulator
asks for it; the protocol classes themselves never import the network.
"""

from .crypto import (
    keygen,
    prove,
    verify,
    schnorr_sign,
    schnorr_verify,
    MerkleTree,
    verify_merkle,
    Commitment,
    CommitmentPool,
    is_valid_public_key,
    SchnorrProof,
)
from .messages import (
    Message,
    make_message,
    BeaconMessage,
    AuthReqMessage,
    AuthRespMessage,
    HandoverReqMessage,
    PreauthMessage,
    BsmMessage,
    message_type,
)
from .registration import (
    Pseudonym,
    pseudonym_leaf,
    create_pseudonyms,
    register_pseudonyms,
)
from .ledger import MockLedger, MockLedgerView
from .vehicle import Vehicle, auth_context, canonical_json
from .rsu import RSU
from .escrow import (
    ShamirSecretSharing,
    ThresholdIdentityEscrow,
    RSUEscrowAgent,
    IdentityEscrowRecord,
)



def create_vehicle(node, env):
    from .sim_app import create_vehicle as create
    return create(node, env)


def create_rsu(node, env):
    from .sim_app import create_rsu as create
    return create(node, env)


def setup(env) -> None:
    from .sim_app import setup as run_setup
    run_setup(env)


__all__ = [
    "create_vehicle",
    "create_rsu",
    "setup",
    "message_type",
    "pseudonym_leaf",
    "MockLedgerView",
    "keygen",
    "prove",
    "verify",
    "schnorr_sign",
    "schnorr_verify",
    "MerkleTree",
    "verify_merkle",
    "Commitment",
    "CommitmentPool",
    "is_valid_public_key",
    "SchnorrProof",
    "Message",
    "make_message",
    "BeaconMessage",
    "AuthReqMessage",
    "AuthRespMessage",
    "HandoverReqMessage",
    "PreauthMessage",
    "BsmMessage",
    "Pseudonym",
    "create_pseudonyms",
    "register_pseudonyms",
    "MockLedger",
    "Vehicle",
    "auth_context",
    "canonical_json",
    "RSU",
    "ShamirSecretSharing",
    "ThresholdIdentityEscrow",
    "RSUEscrowAgent",
    "IdentityEscrowRecord",
]
