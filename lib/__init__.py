"""
mininet-sec-lab — núcleo de detecção para cases de cybersecurity no Mininet.

Filosofia: os detectores são FUNÇÕES PURAS sobre uma lista de eventos de rede
normalizados (dicts). Isso permite:

  1. Testar a lógica de detecção em qualquer máquina (pytest, CI, nuvem) sem
     root nem Mininet, usando traces sintéticos.
  2. Reusar exatamente o mesmo detector nos cenários Mininet, onde os eventos
     vêm de captura real (scapy/tcpdump) em vez de sintéticos.

Só stdlib no núcleo. scapy é opcional e só entra no sensor de captura real.
"""

from .evidence import Evidence, Finding, Severity
from .detectors import (
    DETECTORS,
    detect_arp_spoof,
    detect_rogue_dhcp,
    detect_syn_flood,
    detect_port_scan,
    detect_ssh_bruteforce,
    detect_dns_spoof,
)

__all__ = [
    "Evidence",
    "Finding",
    "Severity",
    "DETECTORS",
    "detect_arp_spoof",
    "detect_rogue_dhcp",
    "detect_syn_flood",
    "detect_port_scan",
    "detect_ssh_bruteforce",
    "detect_dns_spoof",
]

__version__ = "0.1.0"
