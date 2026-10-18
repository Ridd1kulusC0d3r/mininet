#!/usr/bin/env python3
"""C3 — SYN flood / DDoS (T1499/T1498).
Ataque (sandbox): rajada de SYNs half-open contra o serviço. Detecção: pico de
SYN/s em janela + alta fração half-open; nº de origens separa único de distribuído.
attack_cmd de referência: hping3 -S --flood -p 80 10.0.0.20
"""
from _harness import CaseSpec, run_case
from lib import traces as T

SPEC = CaseSpec(
    case_id="case03_syn_flood",
    title="SYN flood contra o servidor (DoS)",
    detector="syn_flood", technique="T1499.001",
    cfg={"syn_rate_pps": 50, "min_syns": 100},
    sim_trace=lambda: T.benign_baseline() + T.syn_flood(),
    attack_cmd="hping3 -S --flood -p 80 10.0.0.20",
)
if __name__ == "__main__":
    import sys
    run_case(SPEC, "real" if "--real" in sys.argv else "sim")
