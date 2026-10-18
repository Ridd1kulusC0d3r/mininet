#!/usr/bin/env python3
"""S9 — Loss / Manipulation of View (ATT&CK ICS T0815).
HMI deixa de refletir o processo real (valor congelado / telemetria obsoleta).
Detecção: divergência exibido↔real acima da tolerância, ou tag sem atualização.
attack_cmd (real): python3 tools/ot_mitm_relay.py --freeze tank.level (relay HMI↔PLC)
"""
from _harness import CaseSpec, run_case
from lib.ot import traces as T

SPEC = CaseSpec(
    case_id="case12_loss_of_view", title="Perda/Manipulação de visão (HMI)",
    detector="loss_of_view", technique="T0815",
    cfg={"tolerance": 0.05, "stale_s": 30},
    sim_trace=lambda: T.loss_of_view(),
    attack_cmd="python3 tools/ot_mitm_relay.py --freeze tank.level", layer="ot")
if __name__ == "__main__":
    import sys; run_case(SPEC, "real" if "--real" in sys.argv else "sim")
