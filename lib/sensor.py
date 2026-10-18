"""
Sensor — transforma captura real (pcap / tcpdump) em eventos normalizados que
alimentam os detectores de `detectors.py`.

scapy é OPCIONAL: se não estiver instalado, `read_pcap` levanta um erro claro,
mas todo o resto do laboratório (detectores + testes sintéticos) continua
funcionando. É o mesmo esquema de evento usado nos traces de teste, então o
detector não sabe (nem precisa saber) se o evento veio de captura ou sintético.
"""

from __future__ import annotations

from typing import Any

try:                                   # scapy é opcional
    from scapy.all import (            # type: ignore
        rdpcap, ARP, DHCP, BOOTP, IP, TCP, UDP, DNS, DNSRR, Ether,
    )
    _HAS_SCAPY = True
except Exception:                      # pragma: no cover - depende do ambiente
    _HAS_SCAPY = False


_DHCP_MSG = {1: "discover", 2: "offer", 3: "request", 5: "ack", 6: "nak"}
_TCP_FLAG_MAP = [("S", 0x02), ("A", 0x10), ("R", 0x04),
                 ("F", 0x01), ("P", 0x08), ("U", 0x20)]


def _flags_to_str(flagval: int) -> str:
    return "".join(ch for ch, bit in _TCP_FLAG_MAP if flagval & bit)


def packet_to_event(pkt) -> dict[str, Any] | None:
    """Converte um pacote scapy em um evento normalizado (ou None se irrelevante)."""
    ts = float(getattr(pkt, "time", 0.0))

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        return {"type": "arp",
                "op": "request" if a.op == 1 else "reply",
                "sender_ip": a.psrc, "sender_mac": a.hwsrc,
                "target_ip": a.pdst, "ts": ts}

    if pkt.haslayer(DHCP):
        opts = {k: v for opt in pkt[DHCP].options
                if isinstance(opt, tuple) for k, v in [opt[:2]]}
        mtype = opts.get("message-type")
        bootp = pkt[BOOTP] if pkt.haslayer(BOOTP) else None
        return {"type": "dhcp",
                "msg": _DHCP_MSG.get(mtype, str(mtype)),
                "server_ip": opts.get("server_id"),
                "server_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
                "offered_ip": getattr(bootp, "yiaddr", None),
                "gateway": opts.get("router"),
                "dns": opts.get("name_server"),
                "ts": ts}

    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        t, ip = pkt[TCP], pkt[IP]
        return {"type": "tcp",
                "src_ip": ip.src, "src_port": int(t.sport),
                "dst_ip": ip.dst, "dst_port": int(t.dport),
                "flags": _flags_to_str(int(t.flags)), "ts": ts}

    if pkt.haslayer(DNS) and pkt.haslayer(IP):
        d, ip = pkt[DNS], pkt[IP]
        if d.qr == 0:   # query
            qname = d.qd.qname.decode().rstrip(".") if d.qd else ""
            return {"type": "dns", "qr": "query", "qname": qname,
                    "answers": [], "src_ip": ip.src, "dst_ip": ip.dst, "ts": ts}
        answers = []
        qname = d.qd.qname.decode().rstrip(".") if d.qd else ""
        for i in range(d.ancount or 0):
            rr = d.an[i] if d.an else None
            if rr is not None and getattr(rr, "type", None) == 1:  # A
                answers.append(rr.rdata if isinstance(rr.rdata, str)
                               else str(rr.rdata))
        return {"type": "dns", "qr": "response", "qname": qname,
                "answers": answers, "src_ip": ip.src, "dst_ip": ip.dst, "ts": ts}

    return None


def read_pcap(path: str) -> list[dict[str, Any]]:
    """Lê um pcap e devolve a lista de eventos normalizados."""
    if not _HAS_SCAPY:
        raise RuntimeError(
            "scapy não encontrado. Instale com 'pip install scapy' para ler "
            "pcaps. Os detectores e a suíte pytest não dependem dele."
        )
    events = [packet_to_event(p) for p in rdpcap(path)]
    return [e for e in events if e is not None]


def has_scapy() -> bool:
    return _HAS_SCAPY
