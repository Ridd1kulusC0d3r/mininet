"""
Harness compartilhado dos cases.

Um "case" é descrito por um CaseSpec. O harness roda em dois modos:

  sim  : usa um trace sintético (lib/traces) — demonstra o case sem root/Mininet.
         É o modo padrão quando Mininet não está disponível.
  real : constrói a topologia no Mininet, executa o ataque ISOLADO no sandbox,
         captura o tráfego no sensor e alimenta o MESMO detector.

Em ambos os modos a saída é idêntica: uma Evidence selada + um assert de que a
detecção disparou. Isso mantém o detector como única fonte de verdade.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.detectors import DETECTORS                       # noqa: E402
from lib.ot.detectors import OT_DETECTORS                 # noqa: E402
from lib.evidence import Evidence                         # noqa: E402

# registro unificado: detectores IT + OT
ALL_DETECTORS = {**DETECTORS, **OT_DETECTORS}


@dataclass
class CaseSpec:
    case_id: str                       # ex. "case01_arp_spoof"
    title: str
    detector: str                      # chave em DETECTORS
    technique: str                     # MITRE ATT&CK
    cfg: dict = field(default_factory=dict)
    sim_trace: Callable[[], list[dict]] = None   # gera eventos sintéticos
    # real mode:
    attack_cmd: str = ""               # comando(s) de ataque no sandbox (doc)
    expect_min_findings: int = 1
    layer: str = "it"                  # "it" (rede) ou "ot" (ICS)


def run_case(spec: CaseSpec, mode: str = "sim",
             out_dir: str = "out") -> Evidence:
    """Executa o case e devolve a Evidence selada. Levanta AssertionError se a
    detecção esperada não disparar.

    mode: "sim"   -> trace sintético (sem root/Mininet)
          "real"  -> Mininet puro (lib/topo.py)
          "mnsec" -> Mininet-Sec nativo (lib/topo_mnsec.py, NetworkTAP+captureDir)
    """
    os.makedirs(out_dir, exist_ok=True)
    detector = ALL_DETECTORS[spec.detector]

    if mode in ("real", "mnsec") and spec.layer == "ot":
        # Modo real OT exige extração protocol-aware (Modbus/OPC UA → evento),
        # p.ex. Zeek/CISA ICSNPP sobre o pcap. É o próximo passo do roadmap
        # (docs/OT-ROADMAP.md). Até lá, os cases OT validam-se em modo sim/pytest.
        raise RuntimeError(
            f"{spec.case_id}: modo '{mode}' OT requer extração protocol-aware "
            "(Zeek/ICSNPP). Suba a topologia com lib/ot/topology.py + "
            "services/ e valide a detecção via modo sim/pytest por enquanto.")

    if mode == "mnsec":
        events = _run_mnsec(spec)
    elif mode == "real":
        events = _run_real(spec)
    else:
        if spec.sim_trace is None:
            raise ValueError(f"{spec.case_id}: sem sim_trace para modo sim")
        events = spec.sim_trace()

    findings = detector(events, spec.cfg)
    ev = Evidence(case=spec.case_id)
    for f in findings:
        ev.add(f)
    sealed = ev.write(os.path.join(out_dir, f"{spec.case_id}.json"))

    ok = len(findings) >= spec.expect_min_findings
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {spec.case_id} — {spec.title}")
    print(f"        técnica {spec.technique} | modo {mode} | "
          f"findings={len(findings)} | sev={sealed['max_severity']} | "
          f"sha256={sealed['sha256'][:12]}…")
    for f in findings:
        print(f"        → {f.title} (conf {f.confidence:.2f})")
    if not ok:
        raise AssertionError(
            f"{spec.case_id}: esperava ≥{spec.expect_min_findings} finding(s), "
            f"obteve {len(findings)}")
    return ev


def _run_real(spec: CaseSpec) -> list[dict]:
    """
    Modo real (host Linux + root + Mininet). Estrutura de referência:

      1. build_lab() sobe a topologia com porta-espelho no sensor.
      2. baseline: tráfego benigno por alguns segundos.
      3. sensor inicia captura (tcpdump -w cap.pcap) na interface espelhada.
      4. attacker executa spec.attack_cmd (ISOLADO no namespace do atacante).
      5. captura é encerrada; sensor.read_pcap() normaliza os eventos.

    Mantido como referência executável; cada case documenta seu attack_cmd.
    """
    from lib.topo import build_lab
    from lib.sensor import read_pcap

    net, nodes = build_lab(mirror=True)
    try:
        sensor, attacker = nodes["sensor"], nodes["attacker"]
        iface = sensor.defaultIntf()
        pcap = f"out/{spec.case_id}.pcap"
        sensor.cmd(f"tcpdump -i {iface} -w {pcap} -U &")
        net.get("victim").cmd("ping -c2 10.0.0.20")      # baseline
        attacker.cmd(spec.attack_cmd)                    # ataque no sandbox
        sensor.cmd("pkill tcpdump")
        return read_pcap(pcap)
    finally:
        net.stop()


def _run_mnsec(spec: CaseSpec) -> list[dict]:
    """
    Modo Mininet-Sec nativo: usa `mnsec` (Mininet_sec + NetworkTAP + captureDir).
    O TAP espelha o enlace monitorado para o sensor e o Mininet_sec grava o pcap
    em captureDir; normalizamos esse pcap e rodamos o detector.
    """
    from lib.topo_mnsec import build_lab_mnsec, capture_path, GW, SERVER
    from lib.sensor import read_pcap

    cap_dir = "out/mnsec-capture"
    net, nodes, tap = build_lab_mnsec(capture_dir=cap_dir)
    try:
        ok, _ = net.startPacketCapture(nodeName1="s1")   # captura do segmento
        nodes["victim"].cmd(f"ping -c2 {SERVER}")        # baseline
        nodes["attacker"].cmd(spec.attack_cmd)           # ataque isolado
        pcap = capture_path(cap_dir)
        if not pcap:
            raise AssertionError(f"{spec.case_id}: nenhum pcap em {cap_dir}")
        return read_pcap(pcap)
    finally:
        net.stop()
