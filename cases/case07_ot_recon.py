#!/usr/bin/env python3
"""S1 — OT asset discovery / recon (ATT&CK ICS T0846/T0842).
Atacante varre portas OT (502/2404/4840) e sonda function codes/assets.
Detecção: origem fora da allowlist tocando muitos ativos/portas/FCs.
attack_cmd (real): nmap -sT -p 502,2404,4840,20000 10.20.0.0/24 ; tools/ot_recon.py
"""
from _harness import CaseSpec, run_case
from lib.ot import traces as T

SPEC = CaseSpec(
    case_id="case07_ot_recon", title="Reconhecimento de ativos OT",
    detector="ot_recon", technique="T0846",
    cfg={"allowed_masters": T.ALLOWED},
    sim_trace=lambda: T.benign_baseline() + T.ot_recon(),
    attack_cmd="nmap -sT -p 502,2404,4840,20000 10.20.0.0/24", layer="ot")
if __name__ == "__main__":
    import sys; run_case(SPEC, "real" if "--real" in sys.argv else "sim")
