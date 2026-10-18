#!/usr/bin/env python3
"""S8 — DoS contra serviço de controle (ATT&CK ICS T0814).
Flood contra Modbus/502 degradando o ciclo de polling. Detecção: taxa alta na
porta OT + correlação com polls falhando / latência de polling no processo.
attack_cmd (real): hping3 -S --flood -p 502 10.20.0.20
"""
from _harness import CaseSpec, run_case
from lib.ot import traces as T

SPEC = CaseSpec(
    case_id="case10_ot_dos", title="DoS contra serviço de controle (Modbus)",
    detector="ot_dos", technique="T0814",
    cfg={"rate_pps": 50, "min_pkts": 100},
    sim_trace=lambda: T.benign_baseline() + T.ot_dos(),
    attack_cmd="hping3 -S --flood -p 502 10.20.0.20", layer="ot")
if __name__ == "__main__":
    import sys; run_case(SPEC, "real" if "--real" in sys.argv else "sim")
