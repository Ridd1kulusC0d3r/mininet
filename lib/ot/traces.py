"""
Traces sintéticos OT — alimentam a suíte pytest e o modo sim dos cases OT.
Determinísticos. Rede do laboratório OT (célula otcell):

  HMI 10.20.0.10 | EWS 10.20.0.11 | PLC/Modbus 10.20.0.20 | OPC UA 10.20.0.30
  Process 10.20.0.40 | Attacker 10.20.0.66 | Sensor 10.20.0.99
"""

from __future__ import annotations

HMI, EWS, PLC, OPC, ATT = ("10.20.0.10", "10.20.0.11", "10.20.0.20",
                           "10.20.0.30", "10.20.0.66")
ALLOWED = [HMI, EWS]


# --------------------------- baseline benigno ----------------------------- #
def benign_baseline(n: int = 60) -> list[dict]:
    ev: list[dict] = []
    t = 0.0
    # inventário
    for aid, ip, role in [("hmi1", HMI, "HMI"), ("ews1", EWS, "EWS"),
                          ("plc1", PLC, "PLC"), ("opc1", OPC, "OPCUA")]:
        ev.append({"type": "asset", "ts": t, "asset_id": aid, "ip": ip,
                   "role": role, "proto": "modbus"}); t += 0.1
    # polling Modbus legítimo (HMI lê registradores do PLC)
    for i in range(n):
        ev.append({"type": "modbus", "ts": t, "src": HMI, "dst": PLC,
                   "asset_id": "plc1", "operation": "read_registers",
                   "object": "holding:40001", "function_code": 3,
                   "authorized": True, "maintenance_window": False}); t += 0.5
        # processo saudável: displayed == value, poll ok
        ev.append({"type": "process", "ts": t, "asset_id": "plc1",
                   "tag": "tank.level", "value": 50 + (i % 5),
                   "displayed": 50 + (i % 5), "poll_latency_ms": 20,
                   "failed_poll": False})
    # EWS faz um write legítimo de setpoint na janela de manutenção
    ev.append({"type": "modbus", "ts": t, "src": EWS, "dst": PLC,
               "asset_id": "plc1", "operation": "write_register",
               "object": "holding:40002", "function_code": 6,
               "before": 100, "after": 110,
               "authorized": True, "maintenance_window": True}); t += 1
    # OPC UA legítimo: usuário autenticado, sessão assinada
    ev.append({"type": "opcua", "ts": t, "src": HMI, "dst": OPC,
               "asset_id": "opc1", "operation": "connect", "node": "",
               "security_mode": "SignAndEncrypt", "auth": "user",
               "accepted": True}); t += 0.2
    ev.append({"type": "opcua", "ts": t, "src": HMI, "dst": OPC,
               "asset_id": "opc1", "operation": "read", "node": "ns=2;i=5",
               "security_mode": "SignAndEncrypt", "auth": "user",
               "accepted": True})
    return ev


# ------------------------------- ataques ---------------------------------- #
def ot_recon(ts0: float = 100.0) -> list[dict]:
    """Atacante varre portas OT e sonda function codes/assets."""
    ev = []
    t = ts0
    # toca várias portas OT em vários alvos
    for host in range(20, 26):
        for port in (502, 2404, 4840):
            ev.append({"type": "tcp", "src_ip": ATT, "src_port": 55000,
                       "dst_ip": f"10.20.0.{host}", "dst_port": port,
                       "flags": "S", "ts": t}); t += 0.01
    # sonda function codes Modbus no PLC
    for fc in range(1, 16):
        ev.append({"type": "modbus", "ts": t, "src": ATT, "dst": PLC,
                   "asset_id": "plc1", "operation": "read_registers",
                   "object": f"probe:{fc}", "function_code": fc}); t += 0.02
    return ev


def modbus_unauth_write(ts0: float = 100.0, critical: bool = True) -> list[dict]:
    """Escrita não autorizada em registrador crítico pelo atacante."""
    obj = "holding:40001" if critical else "holding:40050"
    return [{"type": "modbus", "ts": ts0, "src": ATT, "dst": PLC,
             "asset_id": "plc1", "operation": "write_register",
             "object": obj, "function_code": 6,
             "before": 100, "after": 900,
             "authorized": False, "maintenance_window": False}]


def rogue_master(ts0: float = 100.0) -> list[dict]:
    """EWS rogue: faz reads benignos e depois um comando write."""
    rogue = "10.20.0.77"
    return [
        {"type": "modbus", "ts": ts0, "src": rogue, "dst": PLC,
         "asset_id": "plc1", "operation": "read_registers",
         "object": "holding:40001", "function_code": 3},
        {"type": "modbus", "ts": ts0 + 1, "src": rogue, "dst": PLC,
         "asset_id": "plc1", "operation": "write_coil",
         "object": "coil:00020", "function_code": 5,
         "before": 0, "after": 1, "authorized": False},
    ]


def ot_dos(ts0: float = 100.0, n: int = 600) -> list[dict]:
    """Flood contra Modbus/502 + polls do processo começam a falhar."""
    ev = []
    t = ts0
    for i in range(n):
        ev.append({"type": "tcp", "src_ip": ATT, "src_port": 40000 + (i % 2000),
                   "dst_ip": PLC, "dst_port": 502, "flags": "S", "ts": t})
        t += 0.004
    # impacto operacional: polls falhando e latência alta
    for i in range(10):
        ev.append({"type": "process", "ts": ts0 + i, "asset_id": PLC,
                   "tag": "plc.poll", "value": 0, "failed_poll": True,
                   "poll_latency_ms": 1500})
    return ev


def opcua_anon_write(ts0: float = 100.0) -> list[dict]:
    """Conexão anônima sem segurança escrevendo em nó."""
    return [
        {"type": "opcua", "ts": ts0, "src": ATT, "dst": OPC, "asset_id": "opc1",
         "operation": "connect", "node": "", "security_mode": "None",
         "auth": "anonymous", "accepted": True},
        {"type": "opcua", "ts": ts0 + 0.5, "src": ATT, "dst": OPC,
         "asset_id": "opc1", "operation": "write", "node": "ns=2;i=7",
         "security_mode": "None", "auth": "anonymous", "accepted": True},
    ]


def loss_of_view(ts0: float = 100.0) -> list[dict]:
    """HMI mostra valor congelado enquanto o processo real diverge."""
    ev = []
    for i in range(6):
        ev.append({"type": "process", "ts": ts0 + i, "asset_id": "plc1",
                   "tag": "tank.level", "value": 50 + i * 8,   # real sobe
                   "displayed": 50,                            # HMI congelada
                   "poll_latency_ms": 20, "failed_poll": False})
    return ev
