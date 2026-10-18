#!/usr/bin/env python3
"""C2 — Rogue DHCP (T1557).
Ataque (sandbox): atacante sobe um DHCP que oferece gateway/DNS próprios,
colocando-se como MITM. Detecção: servidor DHCP fora da allowlist respondendo.
attack_cmd de referência: dnsmasq --dhcp-range=... (ver dhcp_masq_files no repo original)
"""
from _harness import CaseSpec, run_case
from lib import traces as T

SPEC = CaseSpec(
    case_id="case02_rogue_dhcp",
    title="Servidor DHCP malicioso (MITM por DHCP)",
    detector="rogue_dhcp", technique="T1557",
    cfg={"allowed_servers": [T.GW_IP], "trusted_gateway": T.GW_IP},
    sim_trace=lambda: T.benign_baseline() + T.rogue_dhcp(),
    attack_cmd="dnsmasq -d --dhcp-range=10.0.0.50,10.0.0.60,1h "
               "--dhcp-option=3,10.0.0.66 --dhcp-option=6,10.0.0.66",
)
if __name__ == "__main__":
    import sys
    run_case(SPEC, "real" if "--real" in sys.argv else "sim")
