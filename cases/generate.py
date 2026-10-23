#!/usr/bin/env python3
"""
Gerador de cases — expande os 50 cenários-template (scenarios/catalog.py) pela
grade de parâmetros e escreve cada case como uma linha em cases/generated/cases.jsonl.

Cada linha é um case concreto e autodescritivo:
  {case_id, scenario, layer, proto, technique, tactic, detector, registry,
   params, expected:{min_findings, min_severity}}

O trace de cada case é materializado SOB DEMANDA (pelo validador/pytest) a partir
de scenario.build(params) — não guardamos milhares de traces, só a receita.

Uso:
  python3 cases/generate.py            # gera cases.jsonl + stats
  python3 cases/generate.py --cap 50   # no máx. 50 cases por cenário
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scenarios.catalog import CATALOG  # noqa: E402

OUT_DIR = "cases/generated"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap", type=int, default=10_000,
                    help="máximo de cases por cenário")
    ap.add_argument("--out", default=f"{OUT_DIR}/cases.jsonl")
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    n = 0
    by_tech, by_proto, by_layer = Counter(), Counter(), Counter()
    with open(args.out, "w", encoding="utf-8") as fh:
        for s in CATALOG:
            for i, p in enumerate(s.params_product(cap=args.cap)):
                row = {
                    "case_id": f"{s.id}-{i:05d}",
                    "scenario": s.id, "layer": s.layer, "proto": s.proto,
                    "technique": s.technique, "tactic": s.tactic,
                    "detector": s.detector, "registry": s.registry,
                    "params": p,
                    "expected": {"min_findings": 1,
                                 "min_severity": s.min_severity},
                }
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                n += 1
                by_tech[s.technique] += 1
                by_proto[s.proto] += 1
                by_layer[s.layer] += 1

    stats = {
        "total_cases": n, "scenarios": len(CATALOG),
        "by_layer": dict(by_layer), "by_protocol": dict(by_proto),
        "by_technique": dict(sorted(by_tech.items())),
        "distinct_techniques": len(by_tech),
    }
    with open(f"{OUT_DIR}/stats.json", "w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2, ensure_ascii=False)

    print(f"Gerados {n} cases de {len(CATALOG)} cenários → {args.out}")
    print(f"  IT={by_layer['it']}  OT={by_layer['ot']}  "
          f"técnicas ATT&CK distintas={len(by_tech)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
