"""
Detectores OT genéricos (multi-protocolo) — funções puras sobre o evento OT
unificado `type == "ot"`, com campo `proto` (modbus/dnp3/s7comm/iec104).

Enquanto `lib/ot/detectors.py` tem detectores por-cenário (e o parser Modbus real),
este módulo generaliza os COMPORTAMENTOS observáveis descritos pelo ATT&CK for ICS
e por analisadores passivos (quietwire, OT-pcap-Analyzer), para que o gerador de
cases (scenarios/) os reuse em qualquer protocolo.

Evento OT unificado (ver `ot_event`):
  {type:"ot", ts, proto, src, dst, asset_id, operation, object, function_code,
   value, before, after, authorized, maintenance_window, broadcast, malformed,
   is_response, in_range}

Contrato: detect_*(events, cfg) -> list[Finding]. Determinístico, sem I/O.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

from ..evidence import Finding, Severity

OT_PORTS = {"modbus": 502, "dnp3": 20000, "s7comm": 102, "iec104": 2404,
            "opcua": 4840, "ethernetip": 44818, "bacnet": 47808, "mqtt": 1883}
WRITE_OPS = {"write", "write_coil", "write_register", "write_multiple",
             "control", "crob", "direct_operate", "setpoint", "command"}
CMD_OPS = WRITE_OPS | {"stop", "restart", "cold_restart", "warm_restart",
                       "program_download", "program_upload", "mode_change"}


def ot_event(proto: str, src: str, dst: str, operation: str, *,
             ts: float = 0.0, **kw) -> dict[str, Any]:
    """Monta um evento OT unificado com defaults sãos."""
    e = {"type": "ot", "proto": proto, "src": src, "dst": dst,
         "operation": operation, "ts": float(ts),
         "asset_id": kw.pop("asset_id", dst),
         "authorized": kw.pop("authorized", True),
         "maintenance_window": kw.pop("maintenance_window", False),
         "broadcast": kw.pop("broadcast", False),
         "malformed": kw.pop("malformed", False),
         "is_response": kw.pop("is_response", False),
         "in_range": kw.pop("in_range", True)}
    e.update(kw)
    return e


def _cfg(cfg: dict | None, **d) -> dict:
    out = dict(d)
    if cfg:
        out.update({k: v for k, v in cfg.items() if v is not None})
    return out


def _ot(events: list[dict], proto: str | None = None) -> list[dict]:
    out = [e for e in events if e.get("type") == "ot"]
    return [e for e in out if e.get("proto") == proto] if proto else out


def _is_write(op: str) -> bool:
    return op in WRITE_OPS


# --------------------------------------------------------------------------- #
def detect_unauth_write(events, cfg=None):
    """Escrita a partir de origem fora da allowlist de masters. T0836."""
    c = _cfg(cfg, allowed_masters=[])
    out = []
    for e in _ot(events):
        if not _is_write(e.get("operation", "")):
            continue
        unauth = (e.get("authorized") is False or
                  (c["allowed_masters"] and e.get("src") not in c["allowed_masters"]))
        if not unauth:
            continue
        out.append(Finding(
            detector="unauth_write", technique="T0836",
            title=f"[{e.get('proto')}] escrita não autorizada de {e.get('src')} "
                  f"em {e.get('object')} ({e.get('before')}→{e.get('after')})",
            severity=Severity.HIGH, confidence=0.9,
            src=e.get("src", ""), dst=e.get("dst", ""),
            evidence={k: e.get(k) for k in
                      ("proto", "src", "object", "before", "after", "operation")}))
    return out[:1]


def detect_out_of_range_write(events, cfg=None):
    """Escrita com valor fora da faixa permitida do objeto. T0836."""
    out = []
    for e in _ot(events):
        if _is_write(e.get("operation", "")) and e.get("in_range") is False:
            out.append(Finding(
                detector="out_of_range_write", technique="T0836",
                title=f"[{e.get('proto')}] escrita fora de faixa em "
                      f"{e.get('object')} (valor {e.get('after')})",
                severity=Severity.HIGH, confidence=0.88,
                src=e.get("src", ""), dst=e.get("dst", ""),
                evidence={k: e.get(k) for k in
                          ("proto", "object", "after", "in_range")}))
    return out[:1]


def detect_func_violation(events, cfg=None):
    """Function code fora da allow-list. T1692.001 (Unauthorized Message)."""
    c = _cfg(cfg, allowed_fcs=[])
    if not c["allowed_fcs"]:
        return []
    out = []
    for e in _ot(events):
        fc = e.get("function_code")
        if fc is not None and fc not in c["allowed_fcs"]:
            out.append(Finding(
                detector="func_violation", technique="T1692.001",
                title=f"[{e.get('proto')}] function code {fc} fora da allow-list",
                severity=Severity.MEDIUM, confidence=0.8,
                src=e.get("src", ""), dst=e.get("dst", ""),
                evidence={"proto": e.get("proto"), "function_code": fc,
                          "allowed_fcs": c["allowed_fcs"]}))
    return out[:1]


def _op_detector(ops: set[str], technique: str, label: str, sev: Severity):
    def _d(events, cfg=None):
        c = _cfg(cfg, allowed_masters=[])
        out = []
        for e in _ot(events):
            if e.get("operation") not in ops:
                continue
            unauth = (e.get("authorized") is False or
                      (c["allowed_masters"] and
                       e.get("src") not in c["allowed_masters"]))
            if not unauth:
                continue
            out.append(Finding(
                detector=label, technique=technique,
                title=f"[{e.get('proto')}] {label} não autorizado de "
                      f"{e.get('src')} em {e.get('dst')}",
                severity=sev, confidence=0.9,
                src=e.get("src", ""), dst=e.get("dst", ""),
                evidence={"proto": e.get("proto"), "operation": e.get("operation"),
                          "src": e.get("src")}))
        return out[:1]
    return _d


detect_restart = _op_detector(
    {"restart", "cold_restart", "warm_restart"}, "T0816", "restart", Severity.HIGH)
detect_stop = _op_detector({"stop"}, "T0881", "stop", Severity.CRITICAL)
detect_program_download = _op_detector(
    {"program_download", "program_upload"}, "T0843", "program_download",
    Severity.CRITICAL)
detect_mode_change = _op_detector(
    {"mode_change"}, "T0858", "mode_change", Severity.HIGH)


def detect_rogue_master(events, cfg=None):
    """Master fora da allowlist emitindo comando/escrita. T0848."""
    c = _cfg(cfg, allowed_masters=[])
    if not c["allowed_masters"]:
        return []
    by_src = defaultdict(lambda: {"cmds": 0, "dsts": set(), "proto": ""})
    for e in _ot(events):
        if e.get("operation") in CMD_OPS:
            s = by_src[e.get("src", "")]
            s["cmds"] += 1
            s["dsts"].add(e.get("dst"))
            s["proto"] = e.get("proto")
    out = []
    for src, s in by_src.items():
        if src in c["allowed_masters"] or s["cmds"] == 0:
            continue
        out.append(Finding(
            detector="rogue_master", technique="T0848",
            title=f"[{s['proto']}] master não autorizado {src} "
                  f"({s['cmds']} comandos)",
            severity=Severity.CRITICAL, confidence=0.9, src=src,
            evidence={"src": src, "commands": s["cmds"],
                      "targets": sorted(str(d) for d in s["dsts"])}))
    return out[:1]


def detect_response_without_request(events, cfg=None):
    """Resposta sem requisição correspondente (spoof). T1692.002."""
    reqs = {(e.get("src"), e.get("dst"), e.get("object"))
            for e in _ot(events) if not e.get("is_response")}
    out = []
    for e in _ot(events):
        if not e.get("is_response"):
            continue
        # resposta vem de dst→src; a requisição seria src→dst
        if (e.get("dst"), e.get("src"), e.get("object")) not in reqs:
            out.append(Finding(
                detector="response_without_request", technique="T1692.002",
                title=f"[{e.get('proto')}] resposta sem requisição de "
                      f"{e.get('src')} para {e.get('object')}",
                severity=Severity.HIGH, confidence=0.82,
                src=e.get("src", ""), dst=e.get("dst", ""),
                evidence={"proto": e.get("proto"), "object": e.get("object")}))
    return out[:1]


def detect_broadcast_command(events, cfg=None):
    """Comando/escrita em broadcast. T1692.001."""
    out = []
    for e in _ot(events):
        if e.get("broadcast") and e.get("operation") in CMD_OPS:
            out.append(Finding(
                detector="broadcast_command", technique="T1692.001",
                title=f"[{e.get('proto')}] comando broadcast ({e.get('operation')})",
                severity=Severity.HIGH, confidence=0.85,
                src=e.get("src", ""),
                evidence={"proto": e.get("proto"), "operation": e.get("operation")}))
    return out[:1]


def detect_flood_dos(events, cfg=None):
    """Enxurrada de requisições/exceções a um alvo. T0814."""
    c = _cfg(cfg, window_s=5.0, rate_thresh=50.0, min_events=100)
    per = defaultdict(list)
    for e in _ot(events):
        per[(e.get("dst"), e.get("proto"))].append(float(e.get("ts", 0.0)))
    out = []
    for (dst, proto), times in per.items():
        if len(times) < c["min_events"]:
            continue
        times.sort()
        peak, i = 0, 0
        for j in range(len(times)):
            while times[j] - times[i] > c["window_s"]:
                i += 1
            peak = max(peak, j - i + 1)
        rate = peak / c["window_s"]
        if rate < c["rate_thresh"]:
            continue
        out.append(Finding(
            detector="flood_dos", technique="T0814",
            title=f"[{proto}] flood contra {dst} ({rate:.0f} req/s)",
            severity=Severity.CRITICAL, confidence=0.9, dst=str(dst),
            evidence={"proto": proto, "dst": dst, "peak_rate": round(rate, 1),
                      "count": len(times)}))
    return out[:1]


def detect_recon_sweep(events, cfg=None):
    """Uma origem tocando muitos alvos/portas OT. T0846."""
    c = _cfg(cfg, allowed_masters=[], hosts_thresh=8)
    by_src = defaultdict(lambda: {"dsts": set(), "proto": ""})
    for e in _ot(events):
        s = by_src[e.get("src", "")]
        s["dsts"].add(e.get("dst"))
        s["proto"] = e.get("proto")
    out = []
    for src, s in by_src.items():
        if c["allowed_masters"] and src in c["allowed_masters"]:
            continue
        if len(s["dsts"]) >= c["hosts_thresh"]:
            out.append(Finding(
                detector="recon_sweep", technique="T0846",
                title=f"[{s['proto']}] varredura de {src} "
                      f"({len(s['dsts'])} alvos)",
                severity=Severity.MEDIUM, confidence=0.84, src=src,
                evidence={"src": src, "hosts": len(s["dsts"])}))
    return out[:1]


def detect_fingerprint(events, cfg=None):
    """Identificação de dispositivo/ponto-tag (device id, read identity). T0888."""
    c = _cfg(cfg, allowed_masters=[], ident_thresh=3)
    by_src = defaultdict(int)
    proto_of = {}
    for e in _ot(events):
        if e.get("operation") in ("read_device_id", "identify", "point_tag",
                                   "read_identity", "detect_mode"):
            by_src[e.get("src", "")] += 1
            proto_of[e.get("src", "")] = e.get("proto")
    out = []
    for src, n in by_src.items():
        if c["allowed_masters"] and src in c["allowed_masters"]:
            continue
        if n >= c["ident_thresh"]:
            out.append(Finding(
                detector="fingerprint", technique="T0888",
                title=f"[{proto_of.get(src)}] fingerprint de dispositivo por {src} "
                      f"({n} consultas)",
                severity=Severity.LOW, confidence=0.78, src=src,
                evidence={"src": src, "queries": n}))
    return out[:1]


GENERIC_DETECTORS: dict[str, Callable[..., list[Finding]]] = {
    "unauth_write": detect_unauth_write,
    "out_of_range_write": detect_out_of_range_write,
    "func_violation": detect_func_violation,
    "restart": detect_restart,
    "stop": detect_stop,
    "program_download": detect_program_download,
    "mode_change": detect_mode_change,
    "rogue_master": detect_rogue_master,
    "response_without_request": detect_response_without_request,
    "broadcast_command": detect_broadcast_command,
    "flood_dos": detect_flood_dos,
    "recon_sweep": detect_recon_sweep,
    "fingerprint": detect_fingerprint,
}
