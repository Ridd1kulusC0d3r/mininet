"""
Detectores — funções puras sobre eventos de rede normalizados.

Contrato de cada detector:
    detect_xxx(events: list[dict], cfg: dict | None = None) -> list[Finding]

`events` é uma lista de dicts normalizados (ver esquema em docs/EVENTOS.md ou
abaixo). Cada detector é determinístico, sem I/O, sem rede: a mesma entrada
produz sempre a mesma saída. É isso que os torna testáveis na nuvem e reusáveis
nos cenários Mininet.

Esquema resumido dos eventos (campo `type`):

  arp  : {type, op: request|reply, sender_ip, sender_mac, target_ip, ts}
  dhcp : {type, msg: discover|offer|request|ack, server_ip, server_mac,
          offered_ip, gateway, dns, ts}
  tcp  : {type, src_ip, src_port, dst_ip, dst_port, flags, ts}
          flags: string com letras S A R F P U (ex. "S", "SA", "R")
  dns  : {type, qr: query|response, qname, answers: [ip,...],
          src_ip, dst_ip, ts}
  auth : {type, service, src_ip, dst_ip, user, result: fail|success, ts}

`ts` é float (segundos). Ângulo de ciência de dados: cada detector devolve, na
evidência, as *features* que dispararam (contagens, taxas, janelas), não só um
booleano — é isso que vira dataset de detecção depois.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

from .evidence import Finding, Severity


# --------------------------------------------------------------------------- #
# utilitários                                                                  #
# --------------------------------------------------------------------------- #
def _cfg(cfg: dict | None, **defaults) -> dict:
    out = dict(defaults)
    if cfg:
        out.update({k: v for k, v in cfg.items() if v is not None})
    return out


def _by_type(events: list[dict], t: str) -> list[dict]:
    return [e for e in events if e.get("type") == t]


def _rate(count: int, span: float) -> float:
    return count / span if span > 0 else float(count)


# --------------------------------------------------------------------------- #
# C1 — ARP spoofing / MITM  (MITRE T1557.002)                                  #
# --------------------------------------------------------------------------- #
def detect_arp_spoof(events: list[dict], cfg: dict | None = None) -> list[Finding]:
    """
    Dispara quando um mesmo IP passa a resolver para MACs diferentes dentro da
    janela (conflito de binding IP↔MAC), sinal clássico de envenenamento de
    cache ARP. Se o IP em conflito for o gateway, a severidade sobe.

    cfg:
      gateway_ip   : IP do gateway (opcional; eleva severidade se afetado)
      known_bindings : {ip: mac} confiáveis (opcional; conflito = alerta forte)
    """
    c = _cfg(cfg, gateway_ip=None, known_bindings={})
    arp = _by_type(events, "arp")

    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    ts_by_ip: dict[str, list[float]] = defaultdict(list)
    for e in arp:
        if e.get("op") == "reply" and e.get("sender_ip") and e.get("sender_mac"):
            ip_to_macs[e["sender_ip"]].add(e["sender_mac"])
            ts_by_ip[e["sender_ip"]].append(float(e.get("ts", 0.0)))

    findings: list[Finding] = []
    for ip, macs in ip_to_macs.items():
        conflict = len(macs) > 1
        known = c["known_bindings"].get(ip)
        impostor = known is not None and any(m != known for m in macs)
        if not (conflict or impostor):
            continue

        is_gw = ip == c["gateway_ip"]
        sev = Severity.CRITICAL if is_gw else Severity.HIGH
        conf = 0.95 if (impostor or is_gw) else 0.8
        findings.append(Finding(
            detector="arp_spoof",
            title=f"Conflito de binding ARP para {ip} "
                  f"({len(macs)} MACs){' [GATEWAY]' if is_gw else ''}",
            severity=sev,
            confidence=conf,
            technique="T1557.002",
            src=sorted(macs)[0],
            dst=ip,
            evidence={
                "ip": ip,
                "observed_macs": sorted(macs),
                "mac_count": len(macs),
                "expected_mac": known,
                "is_gateway": is_gw,
                "reply_count": len(ts_by_ip[ip]),
            },
        ))
    return findings


# --------------------------------------------------------------------------- #
# C2 — Rogue DHCP  (MITRE T1557)                                               #
# --------------------------------------------------------------------------- #
def detect_rogue_dhcp(events: list[dict], cfg: dict | None = None) -> list[Finding]:
    """
    Dispara quando há OFFER/ACK de um servidor DHCP fora da allowlist, ou quando
    mais de um servidor distinto responde na rede. Se o servidor desconhecido
    empurra gateway/DNS próprios (MITM), severidade crítica.

    cfg:
      allowed_servers : [ip, ...] servidores DHCP legítimos
      trusted_gateway : IP de gateway esperado (opcional)
    """
    c = _cfg(cfg, allowed_servers=[], trusted_gateway=None)
    offers = [e for e in _by_type(events, "dhcp")
              if e.get("msg") in ("offer", "ack")]

    servers = {e.get("server_ip") for e in offers if e.get("server_ip")}
    findings: list[Finding] = []

    for e in offers:
        srv = e.get("server_ip")
        if not srv:
            continue
        unknown = bool(c["allowed_servers"]) and srv not in c["allowed_servers"]
        multi = len(servers) > 1 and srv not in c["allowed_servers"]
        if not (unknown or multi):
            continue

        pushes_gw = (c["trusted_gateway"] is not None
                     and e.get("gateway")
                     and e["gateway"] != c["trusted_gateway"])
        sev = Severity.CRITICAL if pushes_gw else Severity.HIGH
        findings.append(Finding(
            detector="rogue_dhcp",
            title=f"Servidor DHCP não autorizado {srv} respondendo na rede",
            severity=sev,
            confidence=0.9 if pushes_gw else 0.82,
            technique="T1557",
            src=srv,
            dst=e.get("offered_ip", ""),
            evidence={
                "rogue_server_ip": srv,
                "rogue_server_mac": e.get("server_mac"),
                "offered_ip": e.get("offered_ip"),
                "pushed_gateway": e.get("gateway"),
                "pushed_dns": e.get("dns"),
                "trusted_gateway": c["trusted_gateway"],
                "distinct_servers_seen": sorted(s for s in servers if s),
            },
        ))
    # de-duplica por servidor (um finding por servidor rogue)
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        key = f.evidence["rogue_server_ip"]
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# --------------------------------------------------------------------------- #
# C3 — SYN flood / DDoS  (MITRE T1499 / T1498)                                 #
# --------------------------------------------------------------------------- #
def detect_syn_flood(events: list[dict], cfg: dict | None = None) -> list[Finding]:
    """
    Dispara quando a taxa de SYNs sem handshake completo para um alvo excede o
    limiar. Mede half-open (SYN sem SYN-ACK/ACK correspondente) e nº de origens
    (distingue flood único de distribuído/spoofado).

    A taxa é o PICO em janela deslizante (não a média do período), para um surto
    curto não ser diluído por tráfego esparso de fundo.

    cfg:
      syn_rate_pps   : limiar de SYN/s por alvo (default 50)
      min_syns       : mínimo absoluto de SYNs para considerar (default 100)
      halfopen_ratio : fração mínima de half-open (default 0.6)
      window_s       : janela do pico de taxa em segundos (default 5)
    """
    c = _cfg(cfg, syn_rate_pps=50.0, min_syns=100, halfopen_ratio=0.6,
             window_s=5.0)
    tcp = _by_type(events, "tcp")

    per_dst: dict[tuple[str, int], dict[str, Any]] = defaultdict(
        lambda: {"syn_ts": [], "synack": 0, "ack": 0, "srcs": set()})

    for e in tcp:
        flags = (e.get("flags") or "").upper()
        dst = (e.get("dst_ip", ""), int(e.get("dst_port", 0)))
        ts = float(e.get("ts", 0.0))
        has_s, has_a = "S" in flags, "A" in flags
        agg = per_dst[dst]
        if has_s and not has_a:          # SYN
            agg["syn_ts"].append(ts)
            agg["srcs"].add(e.get("src_ip", ""))
        elif has_s and has_a:            # SYN-ACK (resposta do alvo)
            agg["synack"] += 1
        elif has_a and not has_s:        # ACK (handshake fechando)
            agg["ack"] += 1

    findings: list[Finding] = []
    for (dip, dport), agg in per_dst.items():
        syns = len(agg["syn_ts"])
        if syns < c["min_syns"]:
            continue
        # pico de SYNs em qualquer janela de window_s (janela deslizante)
        times = sorted(agg["syn_ts"])
        peak, i = 0, 0
        for j in range(len(times)):
            while times[j] - times[i] > c["window_s"]:
                i += 1
            peak = max(peak, j - i + 1)
        rate = _rate(peak, c["window_s"])
        completed = min(agg["ack"], agg["synack"])
        halfopen = max(syns - completed, 0) / syns
        span = max(times[-1] - times[0], 1e-6)
        if rate < c["syn_rate_pps"] or halfopen < c["halfopen_ratio"]:
            continue

        distributed = len(agg["srcs"]) > 10
        findings.append(Finding(
            detector="syn_flood",
            title=f"SYN flood contra {dip}:{dport} "
                  f"({rate:.0f} SYN/s, {len(agg['srcs'])} origens)",
            severity=Severity.CRITICAL if distributed else Severity.HIGH,
            confidence=0.9,
            technique="T1498" if distributed else "T1499.001",
            dst=f"{dip}:{dport}",
            evidence={
                "dst_ip": dip, "dst_port": dport,
                "syn_count": syns, "syn_rate_pps": round(rate, 2),
                "halfopen_ratio": round(halfopen, 3),
                "distinct_sources": len(agg["srcs"]),
                "distributed": distributed,
                "window_s": round(span, 3),
            },
        ))
    return findings


# --------------------------------------------------------------------------- #
# C4 — Port scan  (MITRE T1046)                                                #
# --------------------------------------------------------------------------- #
def detect_port_scan(events: list[dict], cfg: dict | None = None) -> list[Finding]:
    """
    Dispara em varredura vertical (uma origem → muitas portas de um alvo) ou
    horizontal (uma origem → muitos alvos na mesma porta). Usa SYNs de sondagem
    e RSTs de resposta como sinal.

    cfg:
      vertical_ports : nº de portas distintas que caracteriza scan (default 20)
      horizontal_hosts : nº de alvos distintos (default 15)
    """
    c = _cfg(cfg, vertical_ports=20, horizontal_hosts=15)
    tcp = _by_type(events, "tcp")

    vert: dict[tuple[str, str], set[int]] = defaultdict(set)   # (src,dst)->ports
    horiz: dict[tuple[str, int], set[str]] = defaultdict(set)  # (src,port)->dsts
    rst_back: dict[str, int] = defaultdict(int)

    for e in tcp:
        flags = (e.get("flags") or "").upper()
        src, dst = e.get("src_ip", ""), e.get("dst_ip", "")
        dport = int(e.get("dst_port", 0))
        if "S" in flags and "A" not in flags:
            vert[(src, dst)].add(dport)
            horiz[(src, dport)].add(dst)
        if "R" in flags:
            rst_back[dst] += 1  # dst aqui é quem recebe o RST = o scanner

    findings: list[Finding] = []
    for (src, dst), ports in vert.items():
        if len(ports) >= c["vertical_ports"]:
            findings.append(Finding(
                detector="port_scan",
                title=f"Varredura vertical de {src} → {dst} "
                      f"({len(ports)} portas)",
                severity=Severity.MEDIUM,
                confidence=0.85,
                technique="T1046",
                src=src, dst=dst,
                evidence={"scan_type": "vertical", "src_ip": src,
                          "dst_ip": dst, "distinct_ports": len(ports),
                          "sample_ports": sorted(ports)[:20],
                          "rst_received": rst_back.get(src, 0)},
            ))
    for (src, dport), dsts in horiz.items():
        if len(dsts) >= c["horizontal_hosts"]:
            findings.append(Finding(
                detector="port_scan",
                title=f"Varredura horizontal de {src} na porta {dport} "
                      f"({len(dsts)} alvos)",
                severity=Severity.MEDIUM,
                confidence=0.85,
                technique="T1046",
                src=src,
                evidence={"scan_type": "horizontal", "src_ip": src,
                          "dst_port": dport, "distinct_hosts": len(dsts),
                          "sample_hosts": sorted(dsts)[:20]},
            ))
    return findings


# --------------------------------------------------------------------------- #
# C5 — SSH brute force  (MITRE T1110)                                          #
# --------------------------------------------------------------------------- #
def detect_ssh_bruteforce(events: list[dict], cfg: dict | None = None) -> list[Finding]:
    """
    Dispara quando uma origem acumula muitas falhas de autenticação contra um
    alvo dentro da janela. Se um sucesso ocorre após o surto de falhas, marca
    como provável comprometimento (severidade crítica).

    cfg:
      service     : serviço monitorado (default "ssh")
      fail_threshold : falhas que caracterizam brute force (default 10)
      window_s    : janela de agregação em segundos (default 60)
    """
    c = _cfg(cfg, service="ssh", fail_threshold=10, window_s=60.0)
    auth = [e for e in _by_type(events, "auth")
            if e.get("service") == c["service"]]
    auth.sort(key=lambda e: float(e.get("ts", 0.0)))

    per_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in auth:
        per_pair[(e.get("src_ip", ""), e.get("dst_ip", ""))].append(e)

    findings: list[Finding] = []
    for (src, dst), evs in per_pair.items():
        fails = [e for e in evs if e.get("result") == "fail"]
        if len(fails) < c["fail_threshold"]:
            continue
        # janela deslizante: maior nº de falhas em window_s
        times = [float(e.get("ts", 0.0)) for e in fails]
        peak, i = 0, 0
        for j in range(len(times)):
            while times[j] - times[i] > c["window_s"]:
                i += 1
            peak = max(peak, j - i + 1)
        if peak < c["fail_threshold"]:
            continue

        last_fail = times[-1]
        success_after = any(
            e.get("result") == "success" and float(e.get("ts", 0.0)) >= last_fail
            for e in evs)
        users = sorted({e.get("user", "") for e in fails if e.get("user")})
        findings.append(Finding(
            detector="ssh_bruteforce",
            title=f"Brute force {c['service'].upper()} de {src} → {dst} "
                  f"({len(fails)} falhas; pico {peak}/{int(c['window_s'])}s)"
                  + (" + SUCESSO" if success_after else ""),
            severity=Severity.CRITICAL if success_after else Severity.HIGH,
            confidence=0.95 if success_after else 0.88,
            technique="T1110.001",
            src=src, dst=dst,
            evidence={"src_ip": src, "dst_ip": dst,
                      "fail_count": len(fails), "peak_in_window": peak,
                      "window_s": c["window_s"],
                      "users_tried": users[:25],
                      "distinct_users": len(users),
                      "success_after_burst": success_after},
        ))
    return findings


# --------------------------------------------------------------------------- #
# C6 — DNS spoofing  (MITRE T1557)                                             #
# --------------------------------------------------------------------------- #
def detect_dns_spoof(events: list[dict], cfg: dict | None = None) -> list[Finding]:
    """
    Dispara quando um mesmo nome recebe respostas conflitantes (conjuntos de IPs
    diferentes vindos de respondedores diferentes) — corrida de resposta típica
    de envenenamento/spoofing. Também sinaliza respostas sem consulta (unsolicited).

    cfg:
      expected : {qname: [ip, ...]} respostas autoritativas esperadas (opcional)
    """
    c = _cfg(cfg, expected={})
    dns = _by_type(events, "dns")

    queries = {e.get("qname") for e in dns if e.get("qr") == "query"}
    answers_by_name: dict[str, list[dict]] = defaultdict(list)
    for e in dns:
        if e.get("qr") == "response" and e.get("qname"):
            answers_by_name[e["qname"]].append(e)

    findings: list[Finding] = []
    for qname, resps in answers_by_name.items():
        ipsets = {tuple(sorted(r.get("answers", []))) for r in resps}
        responders = {r.get("src_ip") for r in resps if r.get("src_ip")}
        conflict = len(ipsets) > 1 and len(responders) > 1
        unsolicited = qname not in queries and len(resps) >= 1

        expected = c["expected"].get(qname)
        rogue_ip = False
        if expected is not None:
            for r in resps:
                if any(ip not in expected for ip in r.get("answers", [])):
                    rogue_ip = True

        if not (conflict or rogue_ip):
            # unsolicited sozinho é só INFO; ignora para evitar ruído
            continue

        sev = Severity.HIGH if (conflict or rogue_ip) else Severity.LOW
        findings.append(Finding(
            detector="dns_spoof",
            title=f"Respostas DNS conflitantes para {qname} "
                  f"({len(ipsets)} conjuntos de IP, {len(responders)} respondedores)",
            severity=sev,
            confidence=0.9 if rogue_ip else 0.84,
            technique="T1557",
            dst=qname,
            evidence={"qname": qname,
                      "answer_sets": [list(s) for s in ipsets],
                      "responders": sorted(r for r in responders if r),
                      "expected": expected,
                      "rogue_answer": rogue_ip,
                      "unsolicited": unsolicited,
                      "response_count": len(resps)},
        ))
    return findings


# --------------------------------------------------------------------------- #
# registro — usado pelo runner e pela suíte de testes                          #
# --------------------------------------------------------------------------- #
DETECTORS: dict[str, Callable[..., list[Finding]]] = {
    "arp_spoof": detect_arp_spoof,
    "rogue_dhcp": detect_rogue_dhcp,
    "syn_flood": detect_syn_flood,
    "port_scan": detect_port_scan,
    "ssh_bruteforce": detect_ssh_bruteforce,
    "dns_spoof": detect_dns_spoof,
}
