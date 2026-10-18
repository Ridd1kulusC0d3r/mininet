#!/usr/bin/env python3
"""S4 — Rogue master / rogue EWS (ATT&CK ICS T0848).
Estação de engenharia indevida comanda o PLC com comandos formalmente válidos.
Detecção: master fora da allowlist emitindo write/command.
attack_cmd (real): python3 tools/modbus_write.py --host 10.20.0.20 --coil 20 --value 1 --src-rogue
"""
from _harness import CaseSpec, run_case
from lib.ot import traces as T

SPEC = CaseSpec(
    case_id="case09_rogue_master", title="Master não autorizado (rogue EWS)",
    detector="rogue_master", technique="T0848",
    cfg={"allowed_masters": T.ALLOWED},
    sim_trace=lambda: T.benign_baseline() + T.rogue_master(),
    attack_cmd="python3 tools/modbus_write.py --host 10.20.0.20 --coil 20 --value 1", layer="ot")
if __name__ == "__main__":
    import sys; run_case(SPEC, "real" if "--real" in sys.argv else "sim")
