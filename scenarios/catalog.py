"""
Catálogo de ~50 cenários-template de cybersecurity (IT + OT/ICS).

Cada cenário é um TEMPLATE: metadados (técnica/tática ATT&CK, detector) + uma
GRADE de parâmetros + um BUILDER que transforma parâmetros em eventos. O gerador
(cases/generate.py) expande `cenário × grade` em milhares de cases concretos.

Fontes da taxonomia: MITRE ATT&CK for ICS v20, analisadores passivos ICS
(quietwire, OT-pcap-Analyzer) e literatura de datasets ICS/IIoT.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Callable

from lib.detectors import DETECTORS
from lib.ot.generic import GENERIC_DETECTORS, ot_event

# ----- endereços do laboratório -------------------------------------------- #
HMI, EWS, PLC = "10.20.0.10", "10.20.0.11", "10.20.0.20"
ALLOWED = [HMI, EWS]
ROGUES = ["10.20.0.66", "10.20.0.77", "10.10.0.66", "172.16.0.9"]
OT_PROTOS = ["modbus", "dnp3", "s7comm", "iec104"]
GW, GW_MAC, VICTIM, VICTIM_MAC, SERVER = (
    "10.0.0.1", "00:00:00:00:00:01", "10.0.0.10", "00:00:00:00:00:10", "10.0.0.20")


@dataclass
class Scenario:
    id: str
    title: str
    layer: str                 # "it" | "ot"
    proto: str                 # protocolo ou "ip"
    tactic: str
    technique: str
    detector: str              # chave no registro
    registry: str              # "it" | "generic"
    min_severity: str          # severidade mínima esperada
    grid: dict[str, list] = field(default_factory=dict)
    build: Callable[[dict], list[dict]] = None
    cfg: Callable[[dict], dict] = None

    def params_product(self, cap: int = 10_000) -> list[dict]:
        keys = list(self.grid)
        combos = list(itertools.product(*(self.grid[k] for k in keys)))
        return [dict(zip(keys, c)) for c in combos[:cap]]


# =========================================================================== #
# BUILDERS OT (evento unificado type="ot")                                    #
# =========================================================================== #
def _ot_baseline(proto: str) -> list[dict]:
    """Pequena linha de base autorizada (contraste p/ detectores de identidade)."""
    return [ot_event(proto, HMI, PLC, "read_registers", ts=i * 0.5,
                     function_code=3, authorized=True) for i in range(3)]


def _build_ot(detector: str, proto: str, p: dict) -> list[dict]:
    rogue = p.get("src", ROGUES[0])
    ev = _ot_baseline(proto)
    t0 = 100.0
    if detector == "unauth_write":
        ev.append(ot_event(proto, rogue, PLC, "write_register", ts=t0,
                           object=p["object"], before=100, after=p["after"],
                           function_code=6, authorized=False))
    elif detector == "out_of_range_write":
        ev.append(ot_event(proto, rogue, PLC, "write_register", ts=t0,
                           object=p["object"], after=p["value"], in_range=False,
                           function_code=6, authorized=False))
    elif detector == "func_violation":
        ev.append(ot_event(proto, rogue, PLC, "read", ts=t0,
                           object="probe", function_code=p["fc"]))
    elif detector in ("restart", "stop", "program_download", "mode_change"):
        op = {"restart": "cold_restart", "stop": "stop",
              "program_download": "program_download",
              "mode_change": "mode_change"}[detector]
        ev.append(ot_event(proto, rogue, PLC, op, ts=t0, authorized=False))
    elif detector == "rogue_master":
        ev.append(ot_event(proto, rogue, PLC, "read_registers", ts=t0,
                           function_code=3))
        ev.append(ot_event(proto, rogue, PLC, "write_register", ts=t0 + 1,
                           object=p.get("object", "holding:40001"),
                           before=0, after=1, function_code=6, authorized=False))
    elif detector == "response_without_request":
        ev.append(ot_event(proto, PLC, rogue, "read_registers", ts=t0,
                           object=p.get("object", "holding:40001"),
                           is_response=True))
    elif detector == "broadcast_command":
        ev.append(ot_event(proto, rogue, "255.255.255.255", "write", ts=t0,
                           object=p.get("object", "coil:00001"), broadcast=True,
                           authorized=False))
    elif detector == "flood_dos":
        for i in range(p["count"]):
            ev.append(ot_event(proto, rogue, PLC, "read_registers",
                               ts=t0 + i * 0.004, function_code=3))
    elif detector == "recon_sweep":
        for h in range(p["hosts"]):
            ev.append(ot_event(proto, rogue, f"10.20.0.{20 + h}", "read",
                               ts=t0 + h * 0.01, function_code=3))
    elif detector == "fingerprint":
        for i in range(p["n"]):
            ev.append(ot_event(proto, rogue, PLC, "read_device_id",
                               ts=t0 + i * 0.1))
    return ev


def _cfg_ot(detector: str, p: dict) -> dict:
    c = {"allowed_masters": ALLOWED}
    if detector == "func_violation":
        c["allowed_fcs"] = [1, 2, 3, 4]
    if detector == "flood_dos":
        c.update(window_s=5.0, rate_thresh=50.0, min_events=100)
    if detector == "recon_sweep":
        c["hosts_thresh"] = 8
    if detector == "fingerprint":
        c["ident_thresh"] = 3
    return c


# grades por detector OT (modestas; o produto × protocolos gera os milhares)
_OT_GRID = {
    "unauth_write": {"object": [f"holding:{40001 + i}" for i in range(20)],
                     "src": ROGUES, "after": [150, 500, 900, 65535]},
    "out_of_range_write": {"object": [f"holding:{40001 + i}" for i in range(12)],
                           "src": ROGUES, "value": [-1, 99999, 70000, 2**31]},
    "func_violation": {"fc": [8, 17, 20, 43, 66, 90, 110, 125], "src": ROGUES},
    "restart": {"src": ROGUES, "object": [f"node:{i}" for i in range(4)]},
    "stop": {"src": ROGUES, "object": [f"cpu:{i}" for i in range(4)]},
    "program_download": {"src": ROGUES, "object": [f"block:{i}" for i in range(4)]},
    "mode_change": {"src": ROGUES, "object": [f"mode:{i}" for i in range(4)]},
    "rogue_master": {"src": ROGUES, "object": [f"coil:{1 + i:05d}" for i in range(10)]},
    "response_without_request": {"object": [f"holding:{40001 + i}" for i in range(12)],
                                 "src": ROGUES},
    "broadcast_command": {"object": [f"coil:{1 + i:05d}" for i in range(10)],
                          "src": ROGUES},
    "flood_dos": {"count": [300, 600, 900, 1200], "src": ROGUES},
    "recon_sweep": {"hosts": [8, 16, 32, 48, 64], "src": ROGUES},
    "fingerprint": {"n": [3, 6, 9, 12], "src": ROGUES},
}
_OT_META = {  # detector -> (tactic, technique, min_severity)
    "unauth_write": ("Impair Process Control", "T0836", "high"),
    "out_of_range_write": ("Impair Process Control", "T0836", "high"),
    "func_violation": ("Impair Process Control", "T1692.001", "medium"),
    "restart": ("Inhibit Response Function", "T0816", "high"),
    "stop": ("Inhibit Response Function", "T0881", "critical"),
    "program_download": ("Lateral Movement", "T0843", "critical"),
    "mode_change": ("Evasion", "T0858", "high"),
    "rogue_master": ("Initial Access", "T0848", "critical"),
    "response_without_request": ("Evasion", "T1692.002", "high"),
    "broadcast_command": ("Impair Process Control", "T1692.001", "high"),
    "flood_dos": ("Inhibit Response Function", "T0814", "critical"),
    "recon_sweep": ("Discovery", "T0846", "medium"),
    "fingerprint": ("Collection", "T0888", "low"),
}
# quais detectores por protocolo (nem todo comportamento cabe em todo protocolo)
_OT_BY_PROTO = {
    "modbus":  ["unauth_write", "out_of_range_write", "func_violation",
                "flood_dos", "recon_sweep", "fingerprint", "broadcast_command",
                "response_without_request", "rogue_master"],
    "dnp3":    ["unauth_write", "out_of_range_write", "func_violation",
                "flood_dos", "recon_sweep", "restart",
                "response_without_request", "rogue_master", "fingerprint"],
    "s7comm":  ["unauth_write", "func_violation", "stop", "program_download",
                "mode_change", "recon_sweep", "rogue_master", "fingerprint"],
    "iec104":  ["unauth_write", "out_of_range_write", "func_violation",
                "flood_dos", "broadcast_command", "recon_sweep",
                "response_without_request", "rogue_master", "fingerprint"],
}


# =========================================================================== #
# BUILDERS IT (eventos arp/tcp/dns/auth)                                       #
# =========================================================================== #
def _it_baseline() -> list[dict]:
    ev = []
    for ip, mac in [(GW, GW_MAC), (VICTIM, VICTIM_MAC)]:
        ev.append({"type": "arp", "op": "reply", "sender_ip": ip,
                   "sender_mac": mac, "target_ip": VICTIM, "ts": 0.0})
    return ev


def _build_it(detector: str, p: dict) -> list[dict]:
    ev = _it_baseline()
    t = 100.0
    if detector == "arp_spoof":
        for _ in range(p["n_macs"]):
            ev.append({"type": "arp", "op": "reply",
                       "sender_ip": p["ip"], "sender_mac": "00:00:00:00:00:66",
                       "target_ip": VICTIM, "ts": t}); t += 1
    elif detector == "rogue_dhcp":
        ev.append({"type": "dhcp", "msg": "offer", "server_ip": p["server"],
                   "server_mac": "00:00:00:00:00:66", "offered_ip": "10.0.0.50",
                   "gateway": p["gateway"], "dns": p["gateway"], "ts": t})
    elif detector == "syn_flood":
        n = p["n"]
        for i in range(n):
            src = f"10.0.{i % 250}.{(i * 7) % 250}" if p["distributed"] else "10.0.0.66"
            ev.append({"type": "tcp", "src_ip": src, "src_port": 40000 + (i % 2000),
                       "dst_ip": SERVER, "dst_port": p["port"], "flags": "S",
                       "ts": t + i * 0.004})
    elif detector == "port_scan":
        if p["vertical"]:
            for port in range(1, p["count"] + 1):
                ev.append({"type": "tcp", "src_ip": "10.0.0.66", "src_port": 50000,
                           "dst_ip": SERVER, "dst_port": port, "flags": "S",
                           "ts": t}); t += 0.01
        else:
            for h in range(p["count"]):
                ev.append({"type": "tcp", "src_ip": "10.0.0.66", "src_port": 50000,
                           "dst_ip": f"10.0.0.{h + 2}", "dst_port": p["port"],
                           "flags": "S", "ts": t}); t += 0.01
    elif detector == "ssh_bruteforce":
        users = ["root", "admin", "test", "oracle", "user"]
        for i in range(p["fails"]):
            ev.append({"type": "auth", "service": p["service"], "src_ip": "10.0.0.66",
                       "dst_ip": SERVER, "user": users[i % 5], "result": "fail",
                       "ts": t}); t += 1.5
        if p.get("then_success"):
            ev.append({"type": "auth", "service": p["service"], "src_ip": "10.0.0.66",
                       "dst_ip": SERVER, "user": "root", "result": "success", "ts": t})
    elif detector == "dns_spoof":
        name = p["qname"]
        ev.append({"type": "dns", "qr": "query", "qname": name, "answers": [],
                   "src_ip": VICTIM, "dst_ip": GW, "ts": t})
        ev.append({"type": "dns", "qr": "response", "qname": name,
                   "answers": [p["rogue_ip"]], "src_ip": "10.0.0.66",
                   "dst_ip": VICTIM, "ts": t + 0.02})
        ev.append({"type": "dns", "qr": "response", "qname": name,
                   "answers": ["200.1.2.3"], "src_ip": GW, "dst_ip": VICTIM,
                   "ts": t + 0.05})
    return ev


def _cfg_it(detector: str, p: dict) -> dict:
    if detector == "arp_spoof":
        return {"gateway_ip": GW, "known_bindings": {GW: GW_MAC}}
    if detector == "rogue_dhcp":
        return {"allowed_servers": [GW], "trusted_gateway": GW}
    if detector == "ssh_bruteforce":
        return {"service": p["service"], "fail_threshold": 10, "window_s": 60}
    if detector == "dns_spoof":
        return {}
    return {}


# IT scenarios (template, grade)
_IT_SPECS = [
    ("it_arp_spoof_gateway", "ARP spoof do gateway (MITM)", "arp_spoof",
     "Collection", "T0830", "critical", {"n_macs": [2, 3], "ip": [GW]}),
    ("it_arp_spoof_host", "ARP spoof de host", "arp_spoof",
     "Collection", "T0830", "high", {"n_macs": [2, 3], "ip": [VICTIM]}),
    ("it_rogue_dhcp", "Rogue DHCP (MITM)", "rogue_dhcp",
     "Collection", "T0830", "critical",
     {"server": ["10.0.0.66", "10.0.0.67"], "gateway": ["10.0.0.66"]}),
    ("it_syn_flood_single", "SYN flood (origem única)", "syn_flood",
     "Impact", "T0814", "high",
     {"distributed": [False], "n": [400, 800], "port": [80, 443, 22]}),
    ("it_syn_flood_ddos", "SYN flood distribuído (DDoS)", "syn_flood",
     "Impact", "T0814", "critical",
     {"distributed": [True], "n": [600, 1200], "port": [80, 443]}),
    ("it_port_scan_vertical", "Varredura vertical de portas", "port_scan",
     "Discovery", "T0846", "medium",
     {"vertical": [True], "count": [40, 80, 200], "port": [0]}),
    ("it_port_scan_horizontal", "Varredura horizontal de portas", "port_scan",
     "Discovery", "T0846", "medium",
     {"vertical": [False], "count": [20, 40], "port": [445, 22, 3389]}),
    ("it_bruteforce_ssh", "Brute force SSH", "ssh_bruteforce",
     "Lateral Movement", "T0859", "high",
     {"service": ["ssh"], "fails": [15, 30], "then_success": [False]}),
    ("it_bruteforce_ssh_success", "Brute force SSH + sucesso", "ssh_bruteforce",
     "Lateral Movement", "T0859", "critical",
     {"service": ["ssh"], "fails": [20], "then_success": [True]}),
    ("it_bruteforce_telnet", "Brute force Telnet", "ssh_bruteforce",
     "Lateral Movement", "T0859", "high",
     {"service": ["telnet"], "fails": [15, 30], "then_success": [False]}),
    ("it_bruteforce_rdp", "Brute force RDP", "ssh_bruteforce",
     "Lateral Movement", "T0859", "high",
     {"service": ["rdp"], "fails": [15, 30], "then_success": [False]}),
    ("it_bruteforce_smb", "Brute force SMB", "ssh_bruteforce",
     "Lateral Movement", "T0859", "high",
     {"service": ["smb"], "fails": [15, 30], "then_success": [False]}),
    ("it_bruteforce_ftp", "Brute force FTP", "ssh_bruteforce",
     "Lateral Movement", "T0859", "high",
     {"service": ["ftp"], "fails": [15, 30], "then_success": [False]}),
    ("it_dns_spoof", "DNS spoofing", "dns_spoof",
     "Collection", "T0830", "high",
     {"qname": ["banco.example.com", "scada.local", "hist.plant"],
      "rogue_ip": ["6.6.6.6", "1.2.3.4"]}),
    ("it_dns_spoof_exfil", "DNS spoof p/ domínio de exfil", "dns_spoof",
     "Command and Control", "T0869", "high",
     {"qname": ["x.evil.io", "c2.bad.net"], "rogue_ip": ["6.6.6.6"]}),
]


# =========================================================================== #
# CONSTRUÇÃO DO CATÁLOGO                                                        #
# =========================================================================== #
def _make_catalog() -> list[Scenario]:
    cat: list[Scenario] = []
    # IT
    for sid, title, det, tactic, tech, sev, grid in _IT_SPECS:
        cat.append(Scenario(
            id=sid, title=title, layer="it", proto="ip", tactic=tactic,
            technique=tech, detector=det, registry="it", min_severity=sev,
            grid=grid,
            build=(lambda d: (lambda p: _build_it(d, p)))(det),
            cfg=(lambda d: (lambda p: _cfg_it(d, p)))(det)))
    # OT
    for proto, dets in _OT_BY_PROTO.items():
        for det in dets:
            tactic, tech, sev = _OT_META[det]
            cat.append(Scenario(
                id=f"ot_{proto}_{det}",
                title=f"[{proto}] {det.replace('_', ' ')}",
                layer="ot", proto=proto, tactic=tactic, technique=tech,
                detector=det, registry="generic", min_severity=sev,
                grid=_OT_GRID[det],
                build=(lambda d, pr: (lambda p: _build_ot(d, pr, p)))(det, proto),
                cfg=(lambda d: (lambda p: _cfg_ot(d, p)))(det)))
    return cat


CATALOG: list[Scenario] = _make_catalog()


def get(scenario_id: str) -> Scenario | None:
    for s in CATALOG:
        if s.id == scenario_id:
            return s
    return None


def detector_fn(scenario: Scenario):
    reg = DETECTORS if scenario.registry == "it" else GENERIC_DETECTORS
    return reg[scenario.detector]
