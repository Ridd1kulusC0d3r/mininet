"""
Geradores de traces sintéticos de eventos normalizados.

Servem a dois propósitos:
  1. Alimentar a suíte pytest (TP: ataque presente / FP: só tráfego benigno).
  2. Servir de "dublê" quando não há host Mininet, para demonstrar os cases.

Determinísticos: aceitam `seed` e produzem sempre a mesma sequência.
"""

from __future__ import annotations

import random

GW_IP, GW_MAC = "10.0.0.1", "00:00:00:00:00:01"
VICTIM_IP, VICTIM_MAC = "10.0.0.10", "00:00:00:00:00:10"
SERVER_IP = "10.0.0.20"
ATTACKER_IP, ATTACKER_MAC = "10.0.0.66", "00:00:00:00:00:66"


# --------------------------- tráfego benigno ------------------------------- #
def benign_baseline(seed: int = 1, n: int = 200) -> list[dict]:
    """Mistura benigna: ARP normal, DHCP legítimo, TCP estabelecido, DNS ok."""
    r = random.Random(seed)
    ev: list[dict] = []
    t = 0.0
    # ARP: cada IP → um único MAC (sem conflito)
    for ip, mac in [(GW_IP, GW_MAC), (VICTIM_IP, VICTIM_MAC),
                    (SERVER_IP, "00:00:00:00:00:20")]:
        ev.append({"type": "arp", "op": "reply", "sender_ip": ip,
                   "sender_mac": mac, "target_ip": VICTIM_IP, "ts": t})
        t += 0.5
    # DHCP legítimo de um único servidor
    ev.append({"type": "dhcp", "msg": "offer", "server_ip": GW_IP,
               "server_mac": GW_MAC, "offered_ip": VICTIM_IP,
               "gateway": GW_IP, "dns": GW_IP, "ts": t}); t += 1
    ev.append({"type": "dhcp", "msg": "ack", "server_ip": GW_IP,
               "server_mac": GW_MAC, "offered_ip": VICTIM_IP,
               "gateway": GW_IP, "dns": GW_IP, "ts": t}); t += 1
    # TCP: handshakes completos para poucas portas comuns
    for _ in range(n):
        dport = r.choice([80, 443, 22])
        sp = r.randint(1024, 65535)
        ev.append({"type": "tcp", "src_ip": VICTIM_IP, "src_port": sp,
                   "dst_ip": SERVER_IP, "dst_port": dport, "flags": "S", "ts": t})
        ev.append({"type": "tcp", "src_ip": SERVER_IP, "src_port": dport,
                   "dst_ip": VICTIM_IP, "dst_port": sp, "flags": "SA", "ts": t + 0.01})
        ev.append({"type": "tcp", "src_ip": VICTIM_IP, "src_port": sp,
                   "dst_ip": SERVER_IP, "dst_port": dport, "flags": "A", "ts": t + 0.02})
        t += r.uniform(0.05, 0.3)
    # DNS legítimo
    for name, ip in [("example.com", "93.184.216.34"), ("clavis.com.br", "200.1.2.3")]:
        ev.append({"type": "dns", "qr": "query", "qname": name, "answers": [],
                   "src_ip": VICTIM_IP, "dst_ip": GW_IP, "ts": t}); t += 0.1
        ev.append({"type": "dns", "qr": "response", "qname": name, "answers": [ip],
                   "src_ip": GW_IP, "dst_ip": VICTIM_IP, "ts": t}); t += 0.1
    # auth SSH ocasional e bem-sucedida
    for _ in range(3):
        ev.append({"type": "auth", "service": "ssh", "src_ip": VICTIM_IP,
                   "dst_ip": SERVER_IP, "user": "deivison",
                   "result": "success", "ts": t}); t += 5
    return ev


# --------------------------- ataques (TP) ---------------------------------- #
def arp_spoof(ts0: float = 100.0) -> list[dict]:
    """Atacante responde ARP afirmando ser o gateway (IP do GW → MAC atacante)."""
    return [
        {"type": "arp", "op": "reply", "sender_ip": GW_IP, "sender_mac": GW_MAC,
         "target_ip": VICTIM_IP, "ts": ts0},
        {"type": "arp", "op": "reply", "sender_ip": GW_IP,
         "sender_mac": ATTACKER_MAC, "target_ip": VICTIM_IP, "ts": ts0 + 1},
        {"type": "arp", "op": "reply", "sender_ip": GW_IP,
         "sender_mac": ATTACKER_MAC, "target_ip": VICTIM_IP, "ts": ts0 + 2},
    ]


def rogue_dhcp(ts0: float = 100.0) -> list[dict]:
    """DHCP não autorizado oferecendo gateway/DNS do atacante (MITM)."""
    return [
        {"type": "dhcp", "msg": "offer", "server_ip": ATTACKER_IP,
         "server_mac": ATTACKER_MAC, "offered_ip": "10.0.0.50",
         "gateway": ATTACKER_IP, "dns": ATTACKER_IP, "ts": ts0},
        {"type": "dhcp", "msg": "ack", "server_ip": ATTACKER_IP,
         "server_mac": ATTACKER_MAC, "offered_ip": "10.0.0.50",
         "gateway": ATTACKER_IP, "dns": ATTACKER_IP, "ts": ts0 + 0.5},
    ]


def syn_flood(ts0: float = 100.0, n: int = 500, spoofed: bool = False) -> list[dict]:
    """SYNs half-open contra SERVER:80. spoofed=True → muitas origens (DDoS)."""
    ev = []
    t = ts0
    for i in range(n):
        src = f"10.0.{i % 250}.{(i * 7) % 250}" if spoofed else ATTACKER_IP
        ev.append({"type": "tcp", "src_ip": src, "src_port": 40000 + (i % 20000),
                   "dst_ip": SERVER_IP, "dst_port": 80, "flags": "S", "ts": t})
        t += 0.005   # 200 pps
    return ev


def port_scan(ts0: float = 100.0, vertical: bool = True) -> list[dict]:
    """Varredura SYN: vertical (1 alvo, muitas portas) ou horizontal."""
    ev = []
    t = ts0
    if vertical:
        for port in range(1, 61):
            ev.append({"type": "tcp", "src_ip": ATTACKER_IP, "src_port": 50000,
                       "dst_ip": SERVER_IP, "dst_port": port, "flags": "S", "ts": t})
            ev.append({"type": "tcp", "src_ip": SERVER_IP, "src_port": port,
                       "dst_ip": ATTACKER_IP, "dst_port": 50000, "flags": "R", "ts": t + 0.001})
            t += 0.01
    else:
        for host in range(2, 40):
            ev.append({"type": "tcp", "src_ip": ATTACKER_IP, "src_port": 50000,
                       "dst_ip": f"10.0.0.{host}", "dst_port": 445,
                       "flags": "S", "ts": t})
            t += 0.01
    return ev


def ssh_bruteforce(ts0: float = 100.0, fails: int = 25,
                   then_success: bool = False) -> list[dict]:
    """Rajada de falhas SSH de uma origem; opcionalmente termina em sucesso."""
    ev = []
    t = ts0
    users = ["root", "admin", "test", "oracle", "deivison"]
    for i in range(fails):
        ev.append({"type": "auth", "service": "ssh", "src_ip": ATTACKER_IP,
                   "dst_ip": SERVER_IP, "user": users[i % len(users)],
                   "result": "fail", "ts": t})
        t += 1.5
    if then_success:
        ev.append({"type": "auth", "service": "ssh", "src_ip": ATTACKER_IP,
                   "dst_ip": SERVER_IP, "user": "root", "result": "success", "ts": t})
    return ev


def dns_spoof(ts0: float = 100.0) -> list[dict]:
    """Corrida de resposta: resposta forjada do atacante + resposta real do GW."""
    name = "banco.example.com"
    return [
        {"type": "dns", "qr": "query", "qname": name, "answers": [],
         "src_ip": VICTIM_IP, "dst_ip": GW_IP, "ts": ts0},
        {"type": "dns", "qr": "response", "qname": name, "answers": ["6.6.6.6"],
         "src_ip": ATTACKER_IP, "dst_ip": VICTIM_IP, "ts": ts0 + 0.02},
        {"type": "dns", "qr": "response", "qname": name,
         "answers": ["200.147.100.10"], "src_ip": GW_IP,
         "dst_ip": VICTIM_IP, "ts": ts0 + 0.05},
    ]
