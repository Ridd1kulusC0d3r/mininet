"""
Suíte dos detectores OT — roda sem root/Mininet (pytest). TP + FP por detector.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.ot import detectors as D      # noqa: E402
from lib.ot import traces as T         # noqa: E402
from lib.ot.events import default_policy  # noqa: E402
from lib.evidence import Severity      # noqa: E402

POLICY = {"allowed_masters": T.ALLOWED,
          "critical_objects": ["holding:40001", "coil:00017"],
          "maintenance_window": False}


# S1 — recon
def test_ot_recon_tp():
    f = D.detect_ot_recon(T.benign_baseline() + T.ot_recon(),
                          {"allowed_masters": T.ALLOWED})
    assert f and f[0].technique == "T0846"
    assert f[0].evidence["distinct_assets"] >= 5


def test_ot_recon_fp():
    assert D.detect_ot_recon(T.benign_baseline(),
                             {"allowed_masters": T.ALLOWED}) == []


# S2 — modbus unauthorized write
def test_modbus_unauth_write_tp():
    f = D.detect_modbus_unauth_write(T.benign_baseline() + T.modbus_unauth_write(),
                                     POLICY)
    assert f and f[0].severity == Severity.CRITICAL
    assert f[0].evidence["delta"] == 800


def test_modbus_unauth_write_fp():
    # baseline tem writes LEGÍTIMOS (HMI/EWS autorizados) — não pode disparar
    assert D.detect_modbus_unauth_write(T.benign_baseline(), POLICY) == []


# S4 — rogue master
def test_rogue_master_tp():
    f = D.detect_rogue_master(T.benign_baseline() + T.rogue_master(),
                              {"allowed_masters": T.ALLOWED})
    assert f and f[0].severity == Severity.CRITICAL
    assert f[0].evidence["write_count"] == 1


def test_rogue_master_fp():
    assert D.detect_rogue_master(T.benign_baseline(),
                                 {"allowed_masters": T.ALLOWED}) == []


# S8 — OT DoS
def test_ot_dos_tp():
    f = D.detect_ot_dos(T.benign_baseline() + T.ot_dos())
    assert f and f[0].technique == "T0814"
    assert f[0].severity == Severity.CRITICAL      # polls falhando
    assert f[0].evidence["protocol"] == "modbus"


def test_ot_dos_fp():
    assert D.detect_ot_dos(T.benign_baseline()) == []


# S6 — OPC UA anonymous write
def test_opcua_anon_tp():
    f = D.detect_opcua_anon(T.benign_baseline() + T.opcua_anon_write())
    assert f and any(x.severity == Severity.CRITICAL for x in f)


def test_opcua_anon_fp():
    assert D.detect_opcua_anon(T.benign_baseline()) == []


# S9 — loss of view
def test_loss_of_view_tp():
    f = D.detect_loss_of_view(T.loss_of_view())
    assert f and f[0].technique == "T0815"


def test_loss_of_view_fp():
    assert D.detect_loss_of_view(T.benign_baseline()) == []


def test_default_policy_shape():
    p = default_policy()
    assert "allowed_masters" in p and "critical_objects" in p
