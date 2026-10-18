#!/usr/bin/env python3
"""C4 — Port scan (T1046).
Ataque (sandbox): varredura SYN vertical/horizontal de reconhecimento.
Detecção: uma origem tocando muitas portas de um alvo (ou muitos alvos na mesma porta).
attack_cmd de referência: nmap -sS -p1-1024 10.0.0.20
"""
from _harness import CaseSpec, run_case
from lib import traces as T

SPEC = CaseSpec(
    case_id="case04_port_scan",
    title="Varredura de portas (reconhecimento)",
    detector="port_scan", technique="T1046",
    cfg={"vertical_ports": 20, "horizontal_hosts": 15},
    sim_trace=lambda: T.benign_baseline() + T.port_scan(vertical=True),
    attack_cmd="nmap -sS -p1-1024 10.0.0.20",
)
if __name__ == "__main__":
    import sys
    run_case(SPEC, "real" if "--real" in sys.argv else "sim")
