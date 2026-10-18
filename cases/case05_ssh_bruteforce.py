#!/usr/bin/env python3
"""C5 — SSH brute force (T1110).
Ataque (sandbox): rajada de tentativas de login SSH. Detecção: muitas falhas de
uma origem em janela; sucesso após a rajada marca provável comprometimento.
attack_cmd de referência: hydra -L users.txt -P pass.txt ssh://10.0.0.20
"""
from _harness import CaseSpec, run_case
from lib import traces as T

SPEC = CaseSpec(
    case_id="case05_ssh_bruteforce",
    title="Brute force de SSH",
    detector="ssh_bruteforce", technique="T1110.001",
    cfg={"fail_threshold": 10, "window_s": 60},
    sim_trace=lambda: T.benign_baseline() + T.ssh_bruteforce(then_success=True),
    attack_cmd="hydra -L user_pass_lists/usernames.txt "
               "-P user_pass_lists/passwords.txt ssh://10.0.0.20",
)
if __name__ == "__main__":
    import sys
    run_case(SPEC, "real" if "--real" in sys.argv else "sim")
