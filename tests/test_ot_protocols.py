"""
Testes do parser Modbus/TCP — bytes → evento. Rodam sem scapy/Mininet.
Frames construídos à mão (MBAP + PDU).
"""

import os
import sys
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.ot.protocols.modbus import parse_modbus_tcp, object_of  # noqa: E402


def mbap(pdu: bytes, txn=1, unit=1) -> bytes:
    """Monta um quadro Modbus/TCP: MBAP(7) + PDU."""
    length = len(pdu) + 1  # unit + pdu
    return struct.pack(">HHHB", txn, 0, length, unit) + pdu


META = dict(src_ip="10.20.0.66", dst_ip="10.20.0.20",
            src_port=55000, dst_port=502, ts=100.0, asset_id="plc1")


def test_write_single_register_fc6():
    # FC6: addr=0 (holding:40001), value=900
    pdu = struct.pack(">BHH", 6, 0, 900)
    ev = parse_modbus_tcp(mbap(pdu), **META)
    assert ev["type"] == "modbus"
    assert ev["operation"] == "write_register"
    assert ev["function_code"] == 6
    assert ev["object"] == "holding:40001"
    assert ev["after"] == 900
    assert ev["src"] == "10.20.0.66"


def test_write_single_coil_fc5():
    pdu = struct.pack(">BHH", 5, 19, 0xFF00)   # coil addr 19 → coil:00020, ON
    ev = parse_modbus_tcp(mbap(pdu), **META)
    assert ev["operation"] == "write_coil"
    assert ev["object"] == "coil:00020"
    assert ev["after"] == 1


def test_read_holding_fc3():
    pdu = struct.pack(">BHH", 3, 0, 10)
    ev = parse_modbus_tcp(mbap(pdu), **META)
    assert ev["operation"] == "read_registers"
    assert ev["function_code"] == 3
    assert "before" not in ev          # leitura não tem antes/depois


def test_response_is_ignored():
    # resposta: src_port == 502 (não é requisição)
    pdu = struct.pack(">BHH", 6, 0, 900)
    meta = dict(META); meta["src_port"], meta["dst_port"] = 502, 55000
    assert parse_modbus_tcp(mbap(pdu), **meta) is None


def test_non_modbus_payload():
    assert parse_modbus_tcp(b"GET / HTTP/1.1\r\n", **META) is None
    assert parse_modbus_tcp(b"\x00\x01", **META) is None  # curto demais


def test_bad_protocol_id():
    pdu = struct.pack(">BHH", 6, 0, 900)
    frame = struct.pack(">HHHB", 1, 7, len(pdu) + 1, 1) + pdu  # proto_id=7
    assert parse_modbus_tcp(frame, **META) is None


def test_object_mapping():
    assert object_of(3, 0) == "holding:40001"
    assert object_of(1, 16) == "coil:00017"
    assert object_of(4, 0) == "input:30001"
