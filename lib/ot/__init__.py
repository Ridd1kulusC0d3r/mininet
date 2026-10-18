"""
Camada OT/ICS do mininet-sec-lab.

Mantém a MESMA arquitetura da camada IT: detectores são funções puras sobre
eventos normalizados; o mesmo detector é validado por trace sintético (pytest,
sem root) e reusável com captura real no Mininet. A diferença é a SEMÂNTICA:
em vez de arp/tcp/dns, aqui os eventos são operações industriais — Modbus,
OPC UA, estado de processo, mudança de lógica de PLC, alarmes e inventário.

Cada detector aponta uma técnica do MITRE ATT&CK for ICS (ver attack_ics.py).
"""

from .detectors import OT_DETECTORS
from . import traces as ot_traces
from .attack_ics import ICS_TECHNIQUES

__all__ = ["OT_DETECTORS", "ot_traces", "ICS_TECHNIQUES"]
