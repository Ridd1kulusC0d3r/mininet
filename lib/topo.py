"""
Builder de topologia Mininet reutilizável para os cases.

Importa Mininet de forma preguiçosa: o módulo pode ser importado em qualquer
máquina (para os testes de unidade), mas `build_lab()` só funciona num host
Linux com Mininet + root. Topologia padrão de laboratório:

        victim (10.0.0.10) ──┐
       gateway (10.0.0.1) ───┤
      attacker (10.0.0.66) ──┼── s1 ── sensor (porta espelho)
        server (10.0.0.20) ──┘

O `sensor` é um host ligado a uma porta de espelhamento do switch (SPAN),
posição de onde a captura enxerga todo o segmento — o ponto de coleta dos
detectores. Mantemos IPs/MACs fixos para os cenários serem determinísticos.
"""

from __future__ import annotations

LAB = {
    "gateway":  {"ip": "10.0.0.1/24",  "mac": "00:00:00:00:00:01"},
    "victim":   {"ip": "10.0.0.10/24", "mac": "00:00:00:00:00:10"},
    "server":   {"ip": "10.0.0.20/24", "mac": "00:00:00:00:00:20"},
    "attacker": {"ip": "10.0.0.66/24", "mac": "00:00:00:00:00:66"},
    "sensor":   {"ip": "10.0.0.99/24", "mac": "00:00:00:00:00:99"},
}


def build_lab(mirror: bool = True):
    """
    Constrói e devolve um objeto Mininet já iniciado com a topologia LAB.
    Só roda em Linux + root + Mininet instalado. Levanta ImportError claro
    caso contrário.
    """
    try:
        from mininet.net import Mininet
        from mininet.node import OVSSwitch
        from mininet.link import TCLink
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "Mininet não está disponível aqui. Rode os cases num host Linux "
            "com Mininet instalado e como root (sudo). A lógica de detecção "
            "pode ser validada sem Mininet via 'pytest' (tests/)."
        ) from exc

    net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)
    s1 = net.addSwitch("s1", failMode="standalone")
    nodes = {}
    for name, spec in LAB.items():
        nodes[name] = net.addHost(name, ip=spec["ip"], mac=spec["mac"])
        net.addLink(nodes[name], s1)
    net.start()

    if mirror:
        # espelha todo o tráfego do s1 para a porta do sensor (SPAN), para a
        # captura enxergar o segmento inteiro.
        sensor_port = s1.ports[nodes["sensor"].defaultIntf()]
        s1.cmd(
            f"ovs-vsctl -- --id=@p get port {nodes['sensor'].defaultIntf()} "
            f"-- --id=@m create mirror name=m0 select-all=true output-port=@p "
            f"-- set bridge s1 mirrors=@m"
        )
        _ = sensor_port  # documenta a porta usada

    return net, nodes
