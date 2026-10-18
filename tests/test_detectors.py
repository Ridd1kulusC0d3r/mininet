"""
Suíte de verificação dos detectores — roda em QUALQUER máquina (sem root, sem
Mininet). Cada detector tem:

  * um teste de verdadeiro-positivo (TP): o ataque é detectado;
  * um teste de falso-positivo (FP): o baseline benigno NÃO dispara.

É esta suíte que produz o "relatório de testes em nuvem".
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import detectors as D          # noqa: E402
from lib import traces as T             # noqa: E402
from lib.evidence import Severity       # noqa: E402


# --------------------------------------------------------------------------- #
# C1 — ARP spoof                                                               #
# --------------------------------------------------------------------------- #
def test_arp_spoof_tp():
    ev = T.benign_baseline() + T.arp_spoof()
    f = D.detect_arp_spoof(ev, {"gateway_ip": T.GW_IP,
                                "known_bindings": {T.GW_IP: T.GW_MAC}})
    assert f, "deveria detectar envenenamento ARP do gateway"
    assert f[0].severity == Severity.CRITICAL
    assert f[0].evidence["is_gateway"] is True
    assert T.ATTACKER_MAC in f[0].evidence["observed_macs"]


def test_arp_spoof_fp():
    assert D.detect_arp_spoof(T.benign_baseline(),
                              {"gateway_ip": T.GW_IP}) == []


# --------------------------------------------------------------------------- #
# C2 — Rogue DHCP                                                              #
# --------------------------------------------------------------------------- #
def test_rogue_dhcp_tp():
    ev = T.benign_baseline() + T.rogue_dhcp()
    f = D.detect_rogue_dhcp(ev, {"allowed_servers": [T.GW_IP],
                                 "trusted_gateway": T.GW_IP})
    assert f
    assert f[0].severity == Severity.CRITICAL      # empurra gateway próprio
    assert f[0].evidence["rogue_server_ip"] == T.ATTACKER_IP


def test_rogue_dhcp_fp():
    assert D.detect_rogue_dhcp(T.benign_baseline(),
                               {"allowed_servers": [T.GW_IP],
                                "trusted_gateway": T.GW_IP}) == []


# --------------------------------------------------------------------------- #
# C3 — SYN flood                                                               #
# --------------------------------------------------------------------------- #
def test_syn_flood_tp_single():
    f = D.detect_syn_flood(T.benign_baseline() + T.syn_flood())
    assert f and f[0].evidence["distributed"] is False
    assert f[0].evidence["syn_rate_pps"] > 50


def test_syn_flood_tp_distributed():
    f = D.detect_syn_flood(T.syn_flood(spoofed=True))
    assert f and f[0].evidence["distributed"] is True
    assert f[0].severity == Severity.CRITICAL
    assert f[0].technique == "T1498"


def test_syn_flood_fp():
    assert D.detect_syn_flood(T.benign_baseline()) == []


# --------------------------------------------------------------------------- #
# C4 — Port scan                                                               #
# --------------------------------------------------------------------------- #
def test_port_scan_tp_vertical():
    f = D.detect_port_scan(T.port_scan(vertical=True))
    assert any(x.evidence["scan_type"] == "vertical" for x in f)


def test_port_scan_tp_horizontal():
    f = D.detect_port_scan(T.port_scan(vertical=False))
    assert any(x.evidence["scan_type"] == "horizontal" for x in f)


def test_port_scan_fp():
    assert D.detect_port_scan(T.benign_baseline()) == []


# --------------------------------------------------------------------------- #
# C5 — SSH brute force                                                         #
# --------------------------------------------------------------------------- #
def test_ssh_bruteforce_tp():
    f = D.detect_ssh_bruteforce(T.benign_baseline() + T.ssh_bruteforce())
    assert f and f[0].severity == Severity.HIGH


def test_ssh_bruteforce_tp_with_success():
    f = D.detect_ssh_bruteforce(T.ssh_bruteforce(then_success=True))
    assert f and f[0].severity == Severity.CRITICAL
    assert f[0].evidence["success_after_burst"] is True


def test_ssh_bruteforce_fp():
    assert D.detect_ssh_bruteforce(T.benign_baseline()) == []


# --------------------------------------------------------------------------- #
# C6 — DNS spoof                                                               #
# --------------------------------------------------------------------------- #
def test_dns_spoof_tp():
    f = D.detect_dns_spoof(T.benign_baseline() + T.dns_spoof())
    assert f
    assert any("6.6.6.6" in s for x in f for s in x.evidence["answer_sets"])


def test_dns_spoof_tp_expected_list():
    f = D.detect_dns_spoof(
        T.dns_spoof(),
        {"expected": {"banco.example.com": ["200.147.100.10"]}})
    assert f and f[0].evidence["rogue_answer"] is True


def test_dns_spoof_fp():
    assert D.detect_dns_spoof(T.benign_baseline()) == []


# --------------------------------------------------------------------------- #
# evidência / cadeia de custódia                                               #
# --------------------------------------------------------------------------- #
def test_evidence_seal_and_verify(tmp_path):
    from lib.evidence import Evidence
    ev = Evidence(case="selftest")
    for f in D.detect_arp_spoof(T.arp_spoof(),
                                {"gateway_ip": T.GW_IP,
                                 "known_bindings": {T.GW_IP: T.GW_MAC}}):
        ev.add(f)
    path = tmp_path / "r.json"
    ev.write(str(path))
    assert Evidence.verify(str(path)) is True
    # adulteração quebra a verificação
    data = path.read_text().replace("CRITICAL".lower(), "low")
    path.write_text(data)
    assert Evidence.verify(str(path)) is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
