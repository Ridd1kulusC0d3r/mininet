# Camada OT/ICS — roadmap, referências e recursos externos

Síntese das pesquisas que motivaram a camada `lib/ot/`. O que **executa no
Mininet** já está no repo (detectores, traces, cases, topologia, serviços,
ferramentas). Este documento registra o restante — repos externos, datasets e
roadmap — como **referência**, sem vendorizar código de terceiros (licenças).

## O que já está implementado (roda/testa aqui)

| Área | Arquivos |
|---|---|
| Esquema de eventos OT | `lib/ot/events.py`, `docs/EVENTOS.md` |
| Detectores OT (puros) | `lib/ot/detectors.py` (6) |
| Traces sintéticos OT | `lib/ot/traces.py` |
| Mapa MITRE ATT&CK for ICS | `lib/ot/attack_ics.py` |
| Cases S1–S6 | `cases/case07..case12` |
| Testes TP/FP | `tests/test_ot_detectors.py` |
| Topologia OT (otcell) | `lib/ot/topology.py` |
| Serviços (modo real) | `services/modbus_server.py`, `services/opcua_server.py` |
| Ferramentas de ataque (sandbox) | `tools/modbus_write.py`, `tools/ot_recon.py` |

## Cases OT e técnicas (ATT&CK for ICS)

| Case | Cenário | Técnica | Detector |
|---|---|---|---|
| S1 / case07 | OT asset discovery / recon | T0846, T0842 | `ot_recon` |
| S2 / case08 | Unauthorized Modbus write | T0836, T0831 | `modbus_unauth_write` |
| S4 / case09 | Rogue master / rogue EWS | T0848 | `rogue_master` |
| S8 / case10 | DoS contra serviço de controle | T0814 | `ot_dos` |
| S6 / case11 | OPC UA anonymous/insecure write | T0836, T0859 | `opcua_anon` |
| S9 / case12 | Loss / Manipulation of View | T0815 | `loss_of_view` |

Próximos cases do roadmap (não implementados): S3 OT MitM, S5 PLC logic change
(OpenPLC v4 + hash), S7 OPC UA security policy, S10 alarm suppression, S11 IT→OT
pivot (purdue), S12 ICS deception (Conpot), S13 dataset replay (SWaT/BATADAL/HAI).

## Extração protocol-aware — estado atual

**Modbus/TCP: implementado e testado.** `lib/ot/protocols/modbus.py` é um parser
byte-level (stdlib) que converte o payload Modbus/TCP em evento `modbus`;
`lib/ot/sensor.py::read_pcap_ot` extrai esses payloads do pcap (scapy) e deriva
inventário (`asset`). O loop `pcap → evento → detector` está coberto por
`tests/test_ot_protocols.py` (parser, 7 testes) e `tests/test_ot_pcap_e2e.py`
(ponta-a-ponta com pcap sintético). Por isso os cases **S1/S2/S4/S8** (Modbus)
rodam em `--real/--mnsec` via `_run_ot_real` (sobe `otcell` + `services/modbus_server.py`).

**Pendente:** OPC UA (S6) e detecção baseada em processo (S9) precisam de parser
OPC UA e de um simulador de processo — seguem em SKIP consciente no modo real.
Para fidelidade maior sem reimplementar dissectors, o caminho alternativo é:

```
pcap do sensor → Zeek + CISA ICSNPP → JSON → normalizador → detector
```

## Repositórios externos (referência — manter em external/, não copiar)

| Repo | URL | Licença | Papel |
|---|---|---|---|
| Mininet-Sec | github.com/mininet-sec/mininet-sec | BSD-3 | emulação, NetworkTAP, captura (P0) |
| MiniCPS | github.com/scy-phy/minicps | MIT | processo físico + PLC sobre Mininet (P0) |
| OpenPLC Runtime v4 | github.com/Autonomy-Logic/openplc-runtime | MIT | PLC de software, S5 (P0) |
| CISA ICSNPP | github.com/cisagov/ICSNPP | BSD-3 | parsers Zeek de protocolos ICS (P0) |
| opcua-asyncio (asyncua) | github.com/FreeOpcUa/opcua-asyncio | LGPL-3 | servidor/cliente OPC UA (P1) |
| Conpot | github.com/mushorg/conpot | GPL-2 | honeypot ICS, S12 (P1, externo) |
| SecFlood | github.com/hackinsdn/secflood | MIT | geração de tráfego/carga (P1) |
| GRFICSv3 | github.com/Fortiphyd/GRFICSv3 | GPL-3 | cyber range OT alta fidelidade (P2, externo) |
| ModPwn | github.com/gabrielrovesti/modpwn | ver repo | 6 classes de ataque Modbus/TCP (referência) |
| NEFICS | github.com/Cyphysecurity/NEFICS | ver repo | emulação ICS por JSON (referência) |

> GPL (Conpot, GRFICSv3) e repos sem licença declarada ficam como submódulo/
> container em `external/` (no `.gitignore`), nunca copiados para a árvore MIT.

### Aquisição (quando necessário)

```bash
mkdir -p external
git clone --depth 1 https://github.com/mininet-sec/mininet-sec.git external/mininet-sec
git clone --depth 1 https://github.com/scy-phy/minicps.git external/minicps
git clone --depth 1 https://github.com/cisagov/ICSNPP.git external/ICSNPP
git clone --depth 1 https://github.com/Autonomy-Logic/openplc-runtime.git external/openplc-runtime
# manifesto de commits para reprodutibilidade:
for r in mininet-sec minicps ICSNPP openplc-runtime; do
  printf "%-20s " "$r"; git -C external/$r rev-parse HEAD; done | tee external/COMMITS.txt
```

## Datasets (benchmark de processo — solicitar na origem)

| Dataset | Protocolos | Uso | Origem |
|---|---|---|---|
| SWaT / WADI | — (processo) | envelope físico, S13 | iTrust SUTD (sob solicitação) |
| BATADAL | — (processo) | replay determinístico | batadal.net |
| HAI | HIL | integridade de processo | github.com/icsdataset/hai (Git LFS) |
| Electra | Modbus, S7Comm | FDI/Replay/DoS | IEEE DataPort |
| Dataset IEC-104 | IEC 60870-5-104 | comandos não autorizados, DoS | IEEE DataPort/Zenodo |

> Manter **dois benchmarks separados**: rede (pcap do próprio Mininet + ICSNPP)
> e processo (datasets). Não avaliar detector de rede só com CSV de processo,
> nem anomalia física só com pacotes. No S13, usar split temporal (sem embaralhar
> normal/ataque de uma mesma sequência) para evitar leakage.

## Referências oficiais

- NIST SP 800-82 Rev. 3 — Guide to OT Security (arquitetura, segmentação, Purdue)
- MITRE ATT&CK for ICS — https://attack.mitre.org/matrices/ics/
- NSA + CISA (2022) — Control System Defense: Know the Opponent
- CISA AA22-103A — APT Cyber Tools Targeting ICS/SCADA (PIPEDREAM/INCONTROLLER)
- Mandiant (2022) — INCONTROLLER
- ESET (2022) — Industroyer2 (IEC-104)
- Dragos (2024) — FrostyGoop (primeiro malware a usar Modbus/TCP diretamente)
- Antonioli & Tippenhauer (2015) — MiniCPS (DOI 10.1145/2808705.2808715)
- HackInSDN/UFBA — Mininet-Sec (SBSeg)

## Casos reais → comportamento reproduzido (sem exploits de produto)

| Incidente | Ano | Protocolo | Comportamento no lab |
|---|---|---|---|
| Ucrânia (grid) | 2015 | SCADA | abertura de disjuntor (S2/S4) |
| TRITON/TRISIS | 2017 | — | mudança de lógica (S5, futuro) |
| INDUSTROYER2 | 2022 | IEC-104 | comando anômalo (fase substation) |
| PIPEDREAM | 2022 | Modbus/OPC UA/CODESYS | discovery+write multi-protocolo (S1/S2/S6) |
| FrostyGoop | 2024 | Modbus/TCP | write_register direto (S2) |

Reproduzimos **comportamentos observáveis** (discovery, leitura, write autorizado
em sandbox), nunca exploits de produto.

## Segurança do laboratório

- Ranges privados (10.20.0.0/24) e namespaces isolados; nunca conectar a NIC
  física/produção.
- Detecção por política declarativa (allowlist de masters, objetos críticos,
  janela de manutenção), não por IP hardcoded — para generalizar.
- Resposta: primeiro `audit` (só registra), depois containment com TTL; medir
  impacto colateral (FP de resposta).
