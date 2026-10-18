#!/usr/bin/env python3
"""C1 — ARP spoofing / MITM (T1557.002).
Ataque (sandbox): atacante envia ARP replies forjando ser o gateway, desviando
o tráfego da vítima. Defesa/detecção: conflito de binding IP↔MAC no segmento.
attack_cmd de referência (modo real): arpspoof -i <if> -t 10.0.0.10 10.0.0.1
"""
from _harness import CaseSpec, run_case
from lib import traces as T

SPEC = CaseSpec(
    case_id="case01_arp_spoof",
    title="ARP spoofing contra o gateway (MITM)",
    detector="arp_spoof", technique="T1557.002",
    cfg={"gateway_ip": T.GW_IP, "known_bindings": {T.GW_IP: T.GW_MAC}},
    sim_trace=lambda: T.benign_baseline() + T.arp_spoof(),
    attack_cmd="arpspoof -i attacker-eth0 -t 10.0.0.10 10.0.0.1",
)
if __name__ == "__main__":
    import sys
    run_case(SPEC, "real" if "--real" in sys.argv else "sim")
