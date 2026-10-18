#!/usr/bin/env python3
"""
Runner — executa todos os cases e consolida um relatório.

Uso:
  python3 cases/runner.py            # modo sim (sem root/Mininet) — padrão
  python3 cases/runner.py --real     # modo real (host Linux + root + Mininet)
  python3 cases/runner.py --case case03_syn_flood

Em modo sim roda em qualquer máquina e serve de CI/demonstração. Em modo real
sobe a topologia e gera tráfego de verdade. A saída (evidências seladas) fica
em out/.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _harness import run_case                              # noqa: E402
import case01_arp_spoof, case02_rogue_dhcp, case03_syn_flood  # noqa: E402
import case04_port_scan, case05_ssh_bruteforce, case06_dns_spoof  # noqa: E402
import case07_ot_recon, case08_modbus_unauth_write, case09_rogue_master  # noqa: E402
import case10_ot_dos, case11_opcua_anon_write, case12_loss_of_view  # noqa: E402

CASES = [
    # camada IT (rede)
    case01_arp_spoof.SPEC,
    case02_rogue_dhcp.SPEC,
    case03_syn_flood.SPEC,
    case04_port_scan.SPEC,
    case05_ssh_bruteforce.SPEC,
    case06_dns_spoof.SPEC,
    # camada OT/ICS
    case07_ot_recon.SPEC,
    case08_modbus_unauth_write.SPEC,
    case09_rogue_master.SPEC,
    case10_ot_dos.SPEC,
    case11_opcua_anon_write.SPEC,
    case12_loss_of_view.SPEC,
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Runner dos cases de segurança.")
    ap.add_argument("--real", action="store_true",
                    help="modo real com Mininet puro (root)")
    ap.add_argument("--mnsec", action="store_true",
                    help="modo real com Mininet-Sec nativo (NetworkTAP+captureDir)")
    ap.add_argument("--case", help="roda só um case pelo case_id")
    ap.add_argument("--out", default="out")
    args = ap.parse_args()
    mode = "mnsec" if args.mnsec else ("real" if args.real else "sim")

    specs = [c for c in CASES if (not args.case or c.case_id == args.case)]
    if not specs:
        print(f"case '{args.case}' não encontrado. Disponíveis:")
        for c in CASES:
            print("  ", c.case_id)
        return 2

    print(f"=== mininet-sec-lab | modo {mode} | {len(specs)} case(s) ===\n")
    results = []
    passed = 0
    for spec in specs:
        try:
            ev = run_case(spec, mode, args.out)
            results.append({"case": spec.case_id, "status": "PASS",
                            "findings": len(ev.findings),
                            "severity": ev.max_severity().value,
                            "technique": spec.technique})
            passed += 1
        except AssertionError as exc:
            results.append({"case": spec.case_id, "status": "FAIL",
                            "error": str(exc), "technique": spec.technique})
            print(f"        !! {exc}")
        except ImportError as exc:
            results.append({"case": spec.case_id, "status": "SKIP",
                            "reason": "Mininet indisponível"})
            print(f"[SKIP] {spec.case_id} — {exc}")
        except RuntimeError as exc:
            results.append({"case": spec.case_id, "status": "SKIP",
                            "reason": "extração OT protocol-aware pendente"})
            print(f"[SKIP] {spec.case_id} — {exc}")
        print()

    summary = {"mode": mode, "total": len(specs), "passed": passed,
               "results": results}
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "runner_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    print(f"=== {passed}/{len(specs)} PASS | resumo em "
          f"{args.out}/runner_summary.json ===")
    return 0 if passed == len(specs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
