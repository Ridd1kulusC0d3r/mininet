"""
Topologias OT para Mininet (modo real). Importa Mininet de forma preguiçosa:
o módulo compila em qualquer máquina; build_* só roda em Linux+root+Mininet.

T1 — otcell: célula industrial simples
    HMI/EWS/PLC(Modbus)/OPC UA/attacker/sensor num switch OVS; sensor em porta
    espelho (SPAN) enxerga o segmento. Mapeia 1:1 o padrão victim/attacker/sensor
    da camada IT, trocando host genérico por papéis OT.

T2 — purdue: IT → DMZ → OT (segmentação, para o case de pivô IT→OT)
"""

from __future__ import annotations

OT = {
    "hmi":      {"ip": "10.20.0.10/24", "mac": "00:00:00:00:20:10"},
    "ews":      {"ip": "10.20.0.11/24", "mac": "00:00:00:00:20:11"},
    "plc":      {"ip": "10.20.0.20/24", "mac": "00:00:00:00:20:20"},
    "opcua":    {"ip": "10.20.0.30/24", "mac": "00:00:00:00:20:30"},
    "attacker": {"ip": "10.20.0.66/24", "mac": "00:00:00:00:20:66"},
    "sensor":   {"ip": "10.20.0.99/24", "mac": "00:00:00:00:20:99"},
}


def build_otcell(mirror: bool = True):
    """Sobe a célula OT (T1) e devolve (net, nodes). Linux+root+Mininet."""
    try:
        from mininet.net import Mininet
        from mininet.node import OVSSwitch
        from mininet.link import TCLink
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "Mininet indisponível aqui. Rode num host Linux com Mininet como "
            "root. A lógica de detecção roda sem Mininet via pytest (tests/)."
        ) from exc

    net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)
    s = net.addSwitch("s_ot", failMode="standalone")
    nodes = {}
    for name, spec in OT.items():
        nodes[name] = net.addHost(name, ip=spec["ip"], mac=spec["mac"])
        net.addLink(nodes[name], s)
    net.start()

    if mirror:
        iface = nodes["sensor"].defaultIntf()
        s.cmd(f"ovs-vsctl -- --id=@p get port {iface} "
              f"-- --id=@m create mirror name=mot select-all=true output-port=@p "
              f"-- set bridge s_ot mirrors=@m")
    return net, nodes


# tabela de topos para `mn --custom lib/ot/topology.py --topo otcell`
try:  # só define para o Mininet CLI; não falha fora dele
    from mininet.topo import Topo

    class OTCellTopo(Topo):
        def build(self):
            s = self.addSwitch("s_ot")
            for name, spec in OT.items():
                h = self.addHost(name, ip=spec["ip"], mac=spec["mac"])
                self.addLink(h, s)

    topos = {"otcell": OTCellTopo}
except Exception:  # pragma: no cover
    topos = {}
