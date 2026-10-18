"""ECDSA pseudonym-certificate baseline. Use:  --protocol experiments.baselines.ecdsa_pki
See schemes.py for what is modelled."""

from experiments.baselines.schemes import EcdsaRsu, make

_hooks = make(EcdsaRsu)
setup = _hooks["setup"]
message_type = _hooks["message_type"]
create_vehicle = _hooks["create_vehicle"]
create_rsu = _hooks["create_rsu"]
