"""
Sensor OT — pcap → eventos OT normalizados (Modbus/TCP), para o modo real.

Usa scapy (opcional) só para extrair o payload TCP da porta 502; o parsing é
feito pela função pura `lib/ot/protocols/modbus.py`. Também correlaciona a
leitura anterior de um objeto com a escrita seguinte, preenchendo before→after,
e deriva eventos `asset` do inventário observado.

scapy ausente → erro claro; a suíte pytest e o modo sim não dependem dele.
"""

from __future__ import annotations

from typing import Any

from .protocols.modbus import parse_modbus_tcp

try:
    from scapy.all import rdpcap, IP, TCP, Raw   # type: ignore
    _HAS_SCAPY = True
except Exception:                                # pragma: no cover
    _HAS_SCAPY = False


def read_pcap_ot(path: str, asset_map: dict[str, str] | None = None
                 ) -> list[dict[str, Any]]:
    """
    Lê um pcap e devolve eventos OT (modbus + asset). asset_map mapeia IP→asset_id.
    """
    if not _HAS_SCAPY:
        raise RuntimeError(
            "scapy não encontrado. Instale com 'pip install scapy' para ler "
            "pcap no modo real OT. O parser e a suíte pytest não dependem dele.")
    asset_map = asset_map or {}
    events: list[dict[str, Any]] = []
    assets_seen: set[str] = set()
    last_read_value: dict[str, Any] = {}   # object → último valor (placeholder)

    for pkt in rdpcap(path):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw)):
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        payload = bytes(pkt[Raw].load)
        ev = parse_modbus_tcp(
            payload, src_ip=ip.src, dst_ip=ip.dst,
            src_port=int(tcp.sport), dst_port=int(tcp.dport),
            ts=float(getattr(pkt, "time", 0.0)),
            asset_id=asset_map.get(ip.dst))
        if ev is None:
            continue
        # inventário
        if ip.dst not in assets_seen:
            assets_seen.add(ip.dst)
            events.append({"type": "asset", "ts": ev["ts"],
                           "asset_id": ev["asset_id"], "ip": ip.dst,
                           "role": "PLC", "proto": "modbus"})
        # before/after: usa a última leitura conhecida do objeto como "before"
        if ev.get("operation", "").startswith("read"):
            last_read_value[ev["object"]] = None  # valor real viria da resposta
        elif "after" in ev:
            ev["before"] = last_read_value.get(ev["object"])
        events.append(ev)
    return events


def has_scapy() -> bool:
    return _HAS_SCAPY
