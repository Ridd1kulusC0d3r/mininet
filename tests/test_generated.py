"""
Valida uma AMOSTRA representativa dos cases gerados (um por cenário + amostra
determinística), para manter o pytest rápido. A validação completa dos milhares
está em cases/validate_generated.py (relatório em out/generated_report.json).
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scenarios.catalog import CATALOG, get, detector_fn  # noqa: E402

ORDER = ["info", "low", "medium", "high", "critical"]
JSONL = "cases/generated/cases.jsonl"


def _sample_rows():
    """Um case por cenário (o primeiro) + 1 em cada 50 do corpus, se existir."""
    rows = []
    if os.path.exists(JSONL):
        seen = set()
        with open(JSONL, encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                r = json.loads(line)
                if r["scenario"] not in seen:   # representante de cada cenário
                    seen.add(r["scenario"]); rows.append(r)
                elif i % 50 == 0:               # amostra do restante
                    rows.append(r)
    else:
        for s in CATALOG:                       # sem jsonl: gera na hora
            p = s.params_product()[0]
            rows.append({"case_id": f"{s.id}-live", "scenario": s.id,
                         "params": p,
                         "expected": {"min_findings": 1,
                                      "min_severity": s.min_severity}})
    return rows


SAMPLE = _sample_rows()


def test_catalog_has_50_scenarios():
    assert len(CATALOG) >= 50
    assert len({s.id for s in CATALOG}) == len(CATALOG)   # ids únicos


def test_every_scenario_maps_to_attack():
    for s in CATALOG:
        assert s.technique and s.technique[0] == "T"
        assert s.detector and s.tactic


@pytest.mark.parametrize("row", SAMPLE, ids=[r["case_id"] for r in SAMPLE])
def test_generated_case_fires(row):
    s = get(row["scenario"])
    assert s is not None, f"cenário {row['scenario']} não existe"
    findings = detector_fn(s)(s.build(row["params"]), s.cfg(row["params"]))
    exp = row["expected"]
    assert len(findings) >= exp["min_findings"], \
        f"{row['case_id']}: nenhum finding"
    assert ORDER.index(findings[0].severity.value) >= ORDER.index(exp["min_severity"]), \
        f"{row['case_id']}: severidade {findings[0].severity.value} < {exp['min_severity']}"
