#!/usr/bin/env python3
"""
Valida TODOS os cases gerados (cases/generated/cases.jsonl): materializa o trace
de cada case, roda o detector esperado e confere que dispara na severidade mínima.
Escreve um relatório em out/generated_report.json.

Uso:
  python3 cases/validate_generated.py
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scenarios.catalog import get, detector_fn  # noqa: E402

ORDER = ["info", "low", "medium", "high", "critical"]
JSONL = "cases/generated/cases.jsonl"


def main() -> int:
    if not os.path.exists(JSONL):
        print(f"{JSONL} não existe — rode 'python3 cases/generate.py' primeiro.")
        return 2
    total = passed = 0
    fails: list[str] = []
    by_tech_pass, by_tech_total = Counter(), Counter()

    with open(JSONL, encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            total += 1
            by_tech_total[row["technique"]] += 1
            s = get(row["scenario"])
            if s is None:
                fails.append(row["case_id"])
                continue
            findings = detector_fn(s)(s.build(row["params"]), s.cfg(row["params"]))
            exp = row["expected"]
            ok = (len(findings) >= exp["min_findings"]
                  and findings
                  and ORDER.index(findings[0].severity.value)
                  >= ORDER.index(exp["min_severity"]))
            if ok:
                passed += 1
                by_tech_pass[row["technique"]] += 1
            elif len(fails) < 50:
                fails.append(row["case_id"])

    report = {
        "total": total, "passed": passed, "failed": total - passed,
        "pass_rate": round(passed / total, 4) if total else 0,
        "by_technique": {t: f"{by_tech_pass[t]}/{by_tech_total[t]}"
                         for t in sorted(by_tech_total)},
        "sample_failures": fails[:50],
    }
    os.makedirs("out", exist_ok=True)
    with open("out/generated_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(f"Validados {total} cases | PASS {passed} | FAIL {total - passed} "
          f"| taxa {report['pass_rate']*100:.1f}%")
    print("Relatório: out/generated_report.json")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
