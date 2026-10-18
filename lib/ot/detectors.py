"""
Detectores OT/ICS — funções puras sobre eventos normalizados (lib/ot/events.py).

Contrato idêntico ao da camada IT:
    detect_xxx(events: list[dict], cfg: dict | None = None) -> list[Finding]

Cada detector devolve na evidência as *features* que dispararam (quem, o quê,
valor antes/depois, janela, taxa), não só um booleano — vira dataset de detecção.
A diferença para um IDS TCP comum é a correlação fonte↔operação↔processo: um
`write_register` não é hostil por si; a anomalia é quem enviou, quando, para
qual objeto, com que mudança física e se havia janela de manutenção.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

from ..evidence import Finding, Severity
from .events import OT_PORTS, WRITE_OPS, is_write


def _cfg(cfg: dict | None, **d) -> dict:
    out = dict(d)
    if cfg:
        out.update({k: v for k, v in cfg.items() if v is not None})
    return out


def _by_type(events: list[dict], t: str) -> list[dict]:
    return [e for e in events if e.get("type") == t]


# --------------------------------------------------------------------------- #
# S1 — OT asset discovery / recon  (T0846 / T0842)                            #
# --------------------------------------------------------------------------- #
def detect_ot_recon(events: list[dict], cfg: dict | None = None) -> list[Finding]:
    """
    Dispara quando uma origem fora da allowlist sonda muitos ativos OT, muitas
    portas de controle ou muitos function codes Modbus — reconhecimento.

    cfg: allowed_masters, assets_threshold(=5), fc_threshold(=8), ports_threshold(=3)
    """
    c = _cfg(cfg, allowed_masters=[], assets_threshold=5,
             fc_threshold=8, ports_threshold=3)
    per_src: dict[str, dict[str, set]] = defaultdict(
        lambda: {"assets": set(), "fcs": set(), "ports": set(), "nodes": set()})

    for e in _by_type(events, "modbus"):
        s = per_src[e.get("src", "")]
        s["assets"].add(e.get("asset_id") or e.get("dst"))
        if e.get("function_code") is not None:
            s["fcs"].add(e["function_code"])
    for e in _by_type(events, "opcua"):
        if e.get("operation") in ("connect", "browse"):
            s = per_src[e.get("src", "")]
            s["assets"].add(e.get("asset_id") or e.get("dst"))
            if e.get("node"):
                s["nodes"].add(e["node"])
    for e in _by_type(events, "tcp"):
        dp = int(e.get("dst_port", 0))
        if dp in OT_PORTS:
            s = per_src[e.get("src_ip", "")]
            s["ports"].add(dp)
            s["assets"].add(e.get("dst_ip"))

    findings: list[Finding] = []
    for src, s in per_src.items():
        if c["allowed_masters"] and src in c["allowed_masters"]:
            continue
        hit = (len(s["assets"]) >= c["assets_threshold"]
               or len(s["fcs"]) >= c["fc_threshold"]
               or len(s["ports"]) >= c["ports_threshold"]
               or len(s["nodes"]) >= c["assets_threshold"])
        if not hit:
            continue
        findings.append(Finding(
            detector="ot_recon",
            title=f"Reconhecimento OT de {src} "
                  f"({len(s['assets'])} ativos, {len(s['fcs'])} FCs, "
                  f"{len(s['ports'])} portas)",
            severity=Severity.MEDIUM,
            confidence=0.85,
            technique="T0846",
            src=src,
            evidence={"src": src,
                      "distinct_assets": len(s["assets"]),
                      "distinct_function_codes": sorted(s["fcs"]),
                      "ot_ports": sorted(s["ports"]),
                      "opcua_nodes": len(s["nodes"])},
        ))
    return findings


# --------------------------------------------------------------------------- #
# S2 — Unauthorized Modbus write  (T0836 / T0831)                             #
# --------------------------------------------------------------------------- #
def detect_modbus_unauth_write(events: list[dict],
                               cfg: dict | None = None) -> list[Finding]:
    """
    Dispara em operação de escrita Modbus vinda de origem não autorizada, ou
    fora da janela de manutenção, ou em objeto crítico. Mede a mudança física
    (before→after) para graduar severidade.

    cfg: allowed_masters, critical_objects, maintenance_window
    """
    c = _cfg(cfg, allowed_masters=[], critical_objects=[],
             maintenance_window=False)
    findings: list[Finding] = []
    for e in _by_type(events, "modbus"):
        if not is_write(e.get("operation", "")):
            continue
        src = e.get("src", "")
        unauth_src = bool(c["allowed_masters"]) and src not in c["allowed_masters"]
        flagged = e.get("authorized") is False
        out_of_window = (not c["maintenance_window"]
                         and e.get("maintenance_window") is False
                         and e.get("authorized") is not True)
        critical = e.get("object") in c["critical_objects"]
        if not (unauth_src or flagged or (critical and out_of_window)):
            continue

        before, after = e.get("before"), e.get("after")
        delta = None
        if isinstance(before, (int, float)) and isinstance(after, (int, float)):
            delta = after - before
        sev = Severity.CRITICAL if critical else Severity.HIGH
        findings.append(Finding(
            detector="modbus_unauth_write",
            title=f"Escrita Modbus não autorizada de {src} em "
                  f"{e.get('object')} ({before}→{after})"
                  + (" [CRÍTICO]" if critical else ""),
            severity=sev,
            confidence=0.92,
            technique="T0836",
            src=src, dst=e.get("dst", ""),
            evidence={"src": src, "asset_id": e.get("asset_id"),
                      "object": e.get("object"),
                      "operation": e.get("operation"),
                      "before": before, "after": after, "delta": delta,
                      "unauthorized_source": unauth_src,
                      "critical_object": critical,
                      "maintenance_window": e.get("maintenance_window")},
        ))
    return findings


# --------------------------------------------------------------------------- #
# S4 — Rogue master / rogue EWS  (T0848)                                       #
# --------------------------------------------------------------------------- #
def detect_rogue_master(events: list[dict],
                        cfg: dict | None = None) -> list[Finding]:
    """
    Dispara quando um master FORA da allowlist estabelece sessão e emite comando
    (write/command) a um PLC — mesmo que o comando seja formalmente válido. O
    foco é a IDENTIDADE do master, não o valor escrito.

    cfg: allowed_masters (lista de masters legítimos)
    """
    c = _cfg(cfg, allowed_masters=[])
    if not c["allowed_masters"]:
        return []
    per_src: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"reads": 0, "writes": 0, "targets": set()})
    for e in _by_type(events, "modbus"):
        s = per_src[e.get("src", "")]
        if is_write(e.get("operation", "")):
            s["writes"] += 1
        else:
            s["reads"] += 1
        s["targets"].add(e.get("asset_id") or e.get("dst"))

    findings: list[Finding] = []
    for src, s in per_src.items():
        if src in c["allowed_masters"]:
            continue
        if s["writes"] == 0:
            continue  # só leitura entra em ot_recon, não em rogue master
        findings.append(Finding(
            detector="rogue_master",
            title=f"Master não autorizado {src} comandando PLC "
                  f"({s['writes']} escritas, {s['reads']} leituras)",
            severity=Severity.CRITICAL,
            confidence=0.9,
            technique="T0848",
            src=src,
            evidence={"rogue_master": src,
                      "write_count": s["writes"], "read_count": s["reads"],
                      "targets": sorted(str(t) for t in s["targets"]),
                      "allowed_masters": c["allowed_masters"]},
        ))
    return findings


# --------------------------------------------------------------------------- #
# S8 — DoS contra serviço de controle  (T0814)                                 #
# --------------------------------------------------------------------------- #
def detect_ot_dos(events: list[dict], cfg: dict | None = None) -> list[Finding]:
    """
    Dispara quando há enxurrada contra porta de controle (502/2404/4840…) e/ou
    o processo mostra polls falhando / latência de polling subindo. Correlaciona
    rede + impacto operacional, não só contagem de SYNs.

    cfg: rate_pps(=50), window_s(=5), min_pkts(=100),
         poll_latency_ms(=500), failed_poll_min(=5)
    """
    c = _cfg(cfg, rate_pps=50.0, window_s=5.0, min_pkts=100,
             poll_latency_ms=500.0, failed_poll_min=5)
    # rede: pacotes para portas OT por alvo
    per_dst: dict[tuple, list[float]] = defaultdict(list)
    for e in _by_type(events, "tcp"):
        dp = int(e.get("dst_port", 0))
        if dp in OT_PORTS:
            per_dst[(e.get("dst_ip", ""), dp)].append(float(e.get("ts", 0.0)))
    # processo: polls falhos / latência por asset
    poll_bad: dict[str, dict[str, float]] = defaultdict(
        lambda: {"failed": 0, "max_lat": 0.0})
    for e in _by_type(events, "process"):
        a = e.get("asset_id", "")
        if e.get("failed_poll"):
            poll_bad[a]["failed"] += 1
        if e.get("poll_latency_ms"):
            poll_bad[a]["max_lat"] = max(poll_bad[a]["max_lat"],
                                         float(e["poll_latency_ms"]))

    findings: list[Finding] = []
    for (dip, dport), times in per_dst.items():
        if len(times) < c["min_pkts"]:
            continue
        times.sort()
        peak, i = 0, 0
        for j in range(len(times)):
            while times[j] - times[i] > c["window_s"]:
                i += 1
            peak = max(peak, j - i + 1)
        rate = peak / c["window_s"]
        if rate < c["rate_pps"]:
            continue
        proto = OT_PORTS.get(dport, "ot")
        impact = poll_bad.get(dip, {"failed": 0, "max_lat": 0.0})
        findings.append(Finding(
            detector="ot_dos",
            title=f"DoS contra {proto} em {dip}:{dport} "
                  f"({rate:.0f} pkt/s; {impact['failed']} polls falhos)",
            severity=Severity.CRITICAL if impact["failed"] >= c["failed_poll_min"]
            else Severity.HIGH,
            confidence=0.9,
            technique="T0814",
            dst=f"{dip}:{dport}",
            evidence={"dst_ip": dip, "dst_port": dport, "protocol": proto,
                      "peak_rate_pps": round(rate, 1),
                      "failed_polls": impact["failed"],
                      "max_poll_latency_ms": impact["max_lat"]},
        ))
    return findings


# --------------------------------------------------------------------------- #
# S6 — OPC UA anonymous / insecure write  (T0836 / T0859)                      #
# --------------------------------------------------------------------------- #
def detect_opcua_anon(events: list[dict], cfg: dict | None = None) -> list[Finding]:
    """
    Dispara em escrita OPC UA aceita com autenticação anônima e/ou security mode
    None (sessão sem assinatura/criptografia). Também sinaliza browse anônimo
    enumerando muitos nós.

    cfg: browse_threshold(=15)
    """
    c = _cfg(cfg, browse_threshold=15)
    opc = _by_type(events, "opcua")
    findings: list[Finding] = []

    for e in opc:
        if (e.get("operation") == "write" and e.get("accepted")
                and (e.get("auth") == "anonymous" or e.get("security_mode") == "None")):
            findings.append(Finding(
                detector="opcua_anon",
                title=f"Escrita OPC UA anônima/insegura aceita em "
                      f"{e.get('node')} (sec={e.get('security_mode')})",
                severity=Severity.CRITICAL,
                confidence=0.9,
                technique="T0836",
                src=e.get("src", ""), dst=e.get("dst", ""),
                evidence={"src": e.get("src"), "node": e.get("node"),
                          "auth": e.get("auth"),
                          "security_mode": e.get("security_mode"),
                          "accepted": e.get("accepted")},
            ))

    browse_by_src: dict[str, int] = defaultdict(int)
    for e in opc:
        if e.get("operation") == "browse" and e.get("auth") == "anonymous":
            browse_by_src[e.get("src", "")] += 1
    for src, n in browse_by_src.items():
        if n >= c["browse_threshold"]:
            findings.append(Finding(
                detector="opcua_anon",
                title=f"Enumeração OPC UA anônima de {src} ({n} nós)",
                severity=Severity.MEDIUM, confidence=0.82,
                technique="T0846", src=src,
                evidence={"src": src, "nodes_browsed": n, "auth": "anonymous"},
            ))
    return findings


# --------------------------------------------------------------------------- #
# S9 — Loss / Manipulation of View  (T0815)                                    #
# --------------------------------------------------------------------------- #
def detect_loss_of_view(events: list[dict],
                        cfg: dict | None = None) -> list[Finding]:
    """
    Dispara quando o valor mostrado na HMI diverge da verdade do processo além
    da tolerância (view manipulada/congelada), ou quando a telemetria de uma tag
    fica obsoleta (sem atualização) enquanto outras seguem — perda de visão.

    cfg: tolerance(=0.05 relativo), stale_s(=30)
    """
    c = _cfg(cfg, tolerance=0.05, stale_s=30.0)
    proc = _by_type(events, "process")
    findings: list[Finding] = []

    # divergência displayed vs value
    for e in proc:
        disp, val = e.get("displayed"), e.get("value")
        if isinstance(disp, (int, float)) and isinstance(val, (int, float)):
            base = max(abs(val), 1e-6)
            if abs(disp - val) / base > c["tolerance"]:
                findings.append(Finding(
                    detector="loss_of_view",
                    title=f"HMI diverge do processo em {e.get('tag')} "
                          f"(exibido {disp} ≠ real {val})",
                    severity=Severity.HIGH, confidence=0.88,
                    technique="T0815",
                    dst=str(e.get("tag")),
                    evidence={"tag": e.get("tag"), "displayed": disp,
                              "actual": val,
                              "abs_error": abs(disp - val),
                              "asset_id": e.get("asset_id")},
                ))

    # staleness por tag
    last_ts: dict[str, float] = {}
    all_ts: list[float] = []
    for e in sorted(proc, key=lambda x: float(x.get("ts", 0.0))):
        if e.get("tag"):
            last_ts[e["tag"]] = float(e.get("ts", 0.0))
            all_ts.append(float(e.get("ts", 0.0)))
    if all_ts:
        now = max(all_ts)
        for tag, ts in last_ts.items():
            if now - ts > c["stale_s"]:
                findings.append(Finding(
                    detector="loss_of_view",
                    title=f"Telemetria obsoleta em {tag} "
                          f"({now - ts:.0f}s sem atualização)",
                    severity=Severity.HIGH, confidence=0.84,
                    technique="T0815", dst=str(tag),
                    evidence={"tag": tag, "stale_seconds": round(now - ts, 1),
                              "last_update_ts": ts},
                ))
    # de-dup por (tag, título)
    seen, uniq = set(), []
    for f in findings:
        k = (f.dst, f.title)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


OT_DETECTORS: dict[str, Callable[..., list[Finding]]] = {
    "ot_recon": detect_ot_recon,
    "modbus_unauth_write": detect_modbus_unauth_write,
    "rogue_master": detect_rogue_master,
    "ot_dos": detect_ot_dos,
    "opcua_anon": detect_opcua_anon,
    "loss_of_view": detect_loss_of_view,
}
