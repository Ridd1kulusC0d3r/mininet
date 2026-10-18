#!/usr/bin/env python3
"""S2 — Unauthorized Modbus write (ATT&CK ICS T0836/T0831).
Escrita não autorizada em registrador crítico (setpoint). Detecção: write de
origem fora da allowlist / fora de janela / em objeto crítico, com delta físico.
attack_cmd (real): python3 tools/modbus_write.py --host 10.20.0.20 --reg 40001 --value 900
"""
from _harness import CaseSpec, run_case
from lib.ot import traces as T

SPEC = CaseSpec(
    case_id="case08_modbus_unauth_write", title="Escrita Modbus não autorizada",
    detector="modbus_unauth_write", technique="T0836",
    cfg={"allowed_masters": T.ALLOWED,
         "critical_objects": ["holding:40001", "coil:00017"],
         "maintenance_window": False},
    sim_trace=lambda: T.benign_baseline() + T.modbus_unauth_write(),
    attack_cmd="python3 tools/modbus_write.py --host 10.20.0.20 --reg 40001 --value 900", layer="ot")
if __name__ == "__main__":
    import sys; run_case(SPEC, "real" if "--real" in sys.argv else "sim")
