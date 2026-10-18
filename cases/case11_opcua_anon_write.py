#!/usr/bin/env python3
"""S6 — OPC UA anonymous/insecure write (ATT&CK ICS T0836/T0859).
Sessão anônima sem SignAndEncrypt escrevendo em nó. Detecção: write aceito com
auth anônima e/ou security mode None; browse anônimo enumerando nós.
attack_cmd (real): python3 tools/opcua_client.py --url opc.tcp://10.20.0.30:4840 --anon --write ns=2;i=7
"""
from _harness import CaseSpec, run_case
from lib.ot import traces as T

SPEC = CaseSpec(
    case_id="case11_opcua_anon_write", title="Escrita OPC UA anônima/insegura",
    detector="opcua_anon", technique="T0836", cfg={},
    sim_trace=lambda: T.benign_baseline() + T.opcua_anon_write(),
    attack_cmd="python3 tools/opcua_client.py --url opc.tcp://10.20.0.30:4840 --anon --write ns=2;i=7", layer="ot")
if __name__ == "__main__":
    import sys; run_case(SPEC, "real" if "--real" in sys.argv else "sim")
