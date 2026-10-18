"""
Evidência estruturada com cadeia de custódia leve (SHA-256), no estilo das
ferramentas DEIVOSINT. Só stdlib.

Um `Finding` é uma observação de detecção (o que, onde, quando, confiança).
Um `Evidence` agrega os findings de um case e sela o conjunto com um hash,
produzindo um relatório JSON determinístico e verificável.
"""

from __future__ import annotations

import hashlib
import json
import platform
import socket
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Uma observação de detecção."""

    detector: str                 # id do detector, ex. "arp_spoof"
    title: str                    # resumo legível
    severity: Severity
    confidence: float             # 0.0 .. 1.0
    technique: str = ""           # MITRE ATT&CK, ex. "T1557.002"
    src: str = ""                 # origem suspeita (IP/MAC)
    dst: str = ""                 # alvo
    evidence: dict[str, Any] = field(default_factory=dict)  # features que dispararam
    first_seen: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Evidence:
    """
    Agrega findings de um case e sela o conjunto.

    Uso:
        ev = Evidence(case="case01_arp_spoof")
        ev.add(finding)
        report = ev.seal()           # dict pronto para JSON
        ev.write("out/case01.json")  # grava selado
    """

    case: str
    started_at: str = field(default_factory=_now)
    host: str = field(default_factory=socket.gethostname)
    platform: str = field(default_factory=lambda: platform.platform())
    findings: list[Finding] = field(default_factory=list)
    _sealed: dict[str, Any] | None = field(default=None, repr=False)

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    @property
    def triggered(self) -> bool:
        """True se houve qualquer detecção — base para o assert do case."""
        return len(self.findings) > 0

    def max_severity(self) -> Severity:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                 Severity.HIGH, Severity.CRITICAL]
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=order.index)

    def seal(self) -> dict[str, Any]:
        """
        Produz o relatório selado. O hash cobre o corpo canônico (JSON ordenado),
        de modo que qualquer alteração posterior quebra a verificação.
        """
        body = {
            "case": self.case,
            "started_at": self.started_at,
            "finished_at": _now(),
            "host": self.host,
            "platform": self.platform,
            "finding_count": len(self.findings),
            "max_severity": self.max_severity().value,
            "findings": [f.to_dict() for f in self.findings],
        }
        canonical = json.dumps(body, sort_keys=True, ensure_ascii=False).encode()
        body["sha256"] = hashlib.sha256(canonical).hexdigest()
        body["schema"] = "mininet-sec-lab/evidence/1"
        self._sealed = body
        return body

    def write(self, path: str) -> dict[str, Any]:
        sealed = self._sealed or self.seal()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sealed, fh, indent=2, ensure_ascii=False)
        return sealed

    @staticmethod
    def verify(path: str) -> bool:
        """Revalida um relatório selado: recomputa o hash sobre o corpo."""
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        claimed = data.pop("sha256", None)
        data.pop("schema", None)
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False).encode()
        return claimed == hashlib.sha256(canonical).hexdigest()
