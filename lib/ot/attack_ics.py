"""
Mapa mínimo de técnicas do MITRE ATT&CK for ICS usadas pelos cases OT.

Fonte conceitual: MITRE ATT&CK for ICS (https://attack.mitre.org/matrices/ics/).
Só as técnicas efetivamente referenciadas pelos detectores desta camada.
"""

ICS_TECHNIQUES: dict[str, str] = {
    "T0842": "Network Sniffing",
    "T0846": "Remote System Discovery",
    "T0840": "Network Connection Enumeration",
    "T0836": "Modify Parameter",
    "T0831": "Manipulation of Control",
    "T0855": "Unauthorized Command Message",
    "T0848": "Rogue Master",
    "T0814": "Denial of Service",
    "T0885": "Commonly Used Port",
    "T0859": "Valid Accounts",
    "T0815": "Denial of View",
    "T0856": "Spoof Reporting Message",
    "T0821": "Modify Controller Tasking",
    "T0889": "Modify Program",
    "T0878": "Alarm Suppression",
}


def name(technique_id: str) -> str:
    return ICS_TECHNIQUES.get(technique_id, technique_id)
