#!/usr/bin/env python3
"""C6 — DNS spoofing (T1557).
Ataque (sandbox): atacante corre para responder a consulta DNS com IP forjado,
antes do resolvedor real. Detecção: respostas conflitantes para o mesmo nome.
attack_cmd de referência: dnsspoof -i <if> host banco.example.com
"""
from _harness import CaseSpec, run_case
from lib import traces as T

SPEC = CaseSpec(
    case_id="case06_dns_spoof",
    title="DNS spoofing / corrida de resposta",
    detector="dns_spoof", technique="T1557",
    cfg={"expected": {"banco.example.com": ["200.147.100.10"]}},
    sim_trace=lambda: T.benign_baseline() + T.dns_spoof(),
    attack_cmd="dnsspoof -i attacker-eth0 host banco.example.com",
)
if __name__ == "__main__":
    import sys
    run_case(SPEC, "real" if "--real" in sys.argv else "sim")
