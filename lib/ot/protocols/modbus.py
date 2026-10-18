"""
Parser Modbus/TCP — bytes → evento OT normalizado. Só stdlib.

É uma FUNÇÃO PURA sobre bytes, então é testável sem rede, sem scapy e sem
Mininet (ver tests/test_ot_protocols.py). O sensor (lib/ot/sensor.py) extrai o
payload TCP da porta 502 de um pcap e chama esta função.

Quadro Modbus/TCP:
  MBAP (7 bytes): transaction_id(2) protocol_id(2) length(2) unit_id(1)
  PDU: function_code(1) + dados

Direção: uma REQUISIÇÃO vai para dst_port 502 (o mestre é a origem). É assim que
distinguimos requisição de resposta sem estado.
"""

from __future__ import annotations

from typing import Any

# function code → (operation, is_write)
FC = {
    1:  ("read_coils", False),
    2:  ("read_discrete", False),
    3:  ("read_registers", False),
    4:  ("read_input", False),
    5:  ("write_coil", True),
    6:  ("write_register", True),
    15: ("write_multiple", True),
    16: ("write_multiple", True),
}


def _u16(b: bytes, i: int) -> int:
    return (b[i] << 8) | b[i + 1]


def object_of(fc: int, addr: int) -> str:
    """Mapeia (function code, endereço) para um rótulo de objeto legível."""
    if fc in (1, 5, 15):
        return f"coil:{addr + 1:05d}"
    if fc in (2,):
        return f"discrete:{addr + 10001:05d}"
    if fc in (3, 6, 16):
        return f"holding:{addr + 40001:05d}"
    if fc in (4,):
        return f"input:{addr + 30001:05d}"
    return f"addr:{addr}"


def parse_modbus_tcp(payload: bytes, *, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int, ts: float = 0.0,
                     asset_id: str | None = None) -> dict[str, Any] | None:
    """
    Decodifica um payload Modbus/TCP de REQUISIÇÃO (dst_port == 502) em evento.
    Respostas (src_port == 502) e payloads inválidos devolvem None.
    """
    if dst_port != 502:
        return None                      # só requisições (mestre → PLC)
    if len(payload) < 8:
        return None
    proto_id = _u16(payload, 2)
    if proto_id != 0:                    # Modbus/TCP tem protocol id 0
        return None
    unit_id = payload[6]
    fc = payload[7]
    if fc not in FC:
        return None
    operation, is_write = FC[fc]
    data = payload[8:]

    value = None
    before = None
    after = None
    addr = _u16(data, 0) if len(data) >= 2 else 0
    obj = object_of(fc, addr)

    if fc == 5 and len(data) >= 4:                 # write single coil
        value = 1 if _u16(data, 2) == 0xFF00 else 0
        after = value
    elif fc == 6 and len(data) >= 4:               # write single register
        value = _u16(data, 2)
        after = value
    elif fc in (15, 16) and len(data) >= 5:         # write multiple
        qty = _u16(data, 2)
        value = f"{qty} valores"

    ev: dict[str, Any] = {
        "type": "modbus", "ts": float(ts),
        "src": src_ip, "dst": dst_ip,
        "asset_id": asset_id or dst_ip,
        "unit_id": unit_id,
        "function_code": fc, "operation": operation,
        "object": obj,
    }
    if is_write:
        ev["before"] = before
        ev["after"] = after
        ev["value"] = value
    return ev


def is_modbus_request(src_port: int, dst_port: int) -> bool:
    return dst_port == 502
