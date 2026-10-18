"""
Teste ponta-a-ponta OT: gera um pcap Modbus sintético, extrai eventos pelo
sensor (lib/ot/sensor) e roda o detector. Só executa se scapy estiver instalado
(modo real); caso contrário, é pulado. Prova que o loop pcap→evento→detector
fecha sem depender do Mininet.
"""
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

scapy = pytest.importorskip("scapy.all")


def _mbap(pdu, txn=1):
    return struct.pack(">HHHB", txn, 0, len(pdu) + 1, 1) + pdu


def test_pcap_to_finding(tmp_path):
    from scapy.all import IP, TCP, Raw, wrpcap
    from lib.ot.sensor import read_pcap_ot
    from lib.ot.detectors import detect_modbus_unauth_write

    pkts = []
    for i in range(5):  # baseline: HMI lê
        pdu = struct.pack(">BHH", 3, 0, 2)
        pkts.append(IP(src="10.20.0.10", dst="10.20.0.20")
                    / TCP(sport=50000 + i, dport=502) / Raw(_mbap(pdu)))
    # ataque: attacker escreve registrador crítico
    pkts.append(IP(src="10.20.0.66", dst="10.20.0.20")
                / TCP(sport=55000, dport=502)
                / Raw(_mbap(struct.pack(">BHH", 6, 0, 900))))
    p = tmp_path / "m.pcap"
    wrpcap(str(p), pkts)

    ev = read_pcap_ot(str(p), asset_map={"10.20.0.20": "plc1"})
    assert sum(1 for e in ev if e["type"] == "modbus") == 6
    f = detect_modbus_unauth_write(
        ev, {"allowed_masters": ["10.20.0.10", "10.20.0.11"],
             "critical_objects": ["holding:40001"]})
    assert f and f[0].technique == "T0836"
    assert f[0].evidence["after"] == 900
