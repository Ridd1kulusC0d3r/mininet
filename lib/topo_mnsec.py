"""
Topologia NATIVA Mininet-Sec (pacote `mnsec`, projeto mininet-sec/mininet-sec).

Diferente de `lib/topo.py` (Mininet puro), aqui usamos a API real do
Mininet-Sec: `Mininet_sec`, `NetworkTAP` (TAP de software) e `AppManager` para
subir serviços. O TAP é o equivalente nativo da porta-espelho: encaminha A↔B e
copia o tráfego para a porta monitor, onde o `sensor` captura.

Captura: o Mininet_sec já grava pcap em `captureDir`. Lemos esse pcap com
`lib/sensor.py` e alimentamos os mesmos detectores.

Só roda em Linux + root + Mininet-Sec instalado (docker hackinsdn/mininet-sec
ou instalação por fonte). Veja README (seção "Modo real com Mininet-Sec").

Referência de API: examples/firewall.py e examples/sbseg2024.py do
mininet-sec 1.2.0.
"""

from __future__ import annotations

import os

# Rede do lab (consistente com lib/topo.py e os traces)
GW, VICTIM, SERVER, ATTACKER = (
    "10.0.0.1", "10.0.0.10", "10.0.0.20", "10.0.0.66")


def build_lab_mnsec(capture_dir: str = "/tmp/mnsec-capture"):
    """
    Sobe o lab com a API do Mininet-Sec e devolve (net, nodes, tap_name).

    Topologia:
        victim/server/attacker ── s1 (LinuxBridge) ── tap1 (NetworkTAP) ── gateway
                                                          │ (porta monitor)
                                                       sensor

    O TAP espelha o tráfego do enlace s1↔gateway para o sensor. Para enxergar
    também o tráfego intra-segmento (ARP/MITM entre hosts do s1), o Mininet_sec
    grava captura do próprio s1 em captureDir.
    """
    try:
        from mnsec.topo import Topo
        from mnsec.net import Mininet_sec
        from mnsec.nodelib import NetworkTAP
        from mnsec.apps.app_manager import AppManager
        from mininet.node import NullController
        from mininet.nodelib import LinuxBridge
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "Mininet-Sec (pacote `mnsec`) não encontrado. Rode num host Linux "
            "com mininet-sec instalado (docker hackinsdn/mininet-sec ou por "
            "fonte) e como root. A lógica de detecção roda sem ele via pytest."
        ) from exc

    class LabTopo(Topo):
        def build(self):
            victim = self.addHost("victim", ip=f"{VICTIM}/24",
                                  defaultRoute=f"via {GW}")
            server = self.addHost("server", ip=f"{SERVER}/24",
                                  defaultRoute=f"via {GW}")
            attacker = self.addHost("attacker", ip=f"{ATTACKER}/24",
                                    defaultRoute=f"via {GW}")
            gateway = self.addHost("gateway", ip=f"{GW}/24")
            sensor = self.addHost("sensor", ip="10.0.0.99/24")

            s1 = self.addSwitch("s1", cls=LinuxBridge)
            tap1 = self.addSwitch("tap1", cls=NetworkTAP)

            for h in (victim, server, attacker):
                self.addLink(s1, h)
            # enlace monitorado s1 <-> gateway passa pelo TAP (A=s1, B=gateway)
            self.addLink(s1, tap1)           # port_a do TAP
            self.addLink(tap1, gateway)      # port_b do TAP
            # sensor na porta monitor do TAP
            self.addLink(tap1, sensor)

    os.makedirs(capture_dir, exist_ok=True)
    net = Mininet_sec(topo=LabTopo(), controller=NullController,
                      captureDir=capture_dir, captureFileSize="50")
    net.start()

    # serviços no servidor para os cases de scan/brute force terem o que tocar
    AppManager(net, [net.get("server")], "http")
    try:
        AppManager(net, [net.get("server")], "ssh")
    except Exception:
        pass  # ssh pode exigir imagem/serviço extra; segue sem bloquear

    nodes = {n: net.get(n) for n in
             ("victim", "server", "attacker", "gateway", "sensor")}
    return net, nodes, "tap1"


def capture_path(capture_dir: str = "/tmp/mnsec-capture") -> str:
    """Retorna o pcap mais recente gravado pelo Mininet_sec em captureDir."""
    import glob
    pcaps = sorted(glob.glob(os.path.join(capture_dir, "*.pcap")),
                   key=os.path.getmtime)
    return pcaps[-1] if pcaps else ""
