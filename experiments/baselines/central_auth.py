"""Central-authority baseline: every request is checked with the authority.
Use:  --protocol experiments.baselines.central_auth   (ca_rtt_ms / ca_proc_ms in the config)
See schemes.py for what is modelled."""

from experiments.baselines.schemes import CentralRsu, make

_hooks = make(CentralRsu)
setup = _hooks["setup"]
message_type = _hooks["message_type"]
create_vehicle = _hooks["create_vehicle"]
create_rsu = _hooks["create_rsu"]
