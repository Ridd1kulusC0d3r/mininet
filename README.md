# mininet-sec-lab

Cases de teste de cybersecurity para **Mininet**, com foco em **engenharia de
detecção**. Cada case emparelha um ataque executado de forma **isolada no
sandbox emulado** com um **detector** que consome o tráfego e produz
**evidência estruturada e selada** (SHA-256).

> **Suplemento ao [Mininet-Sec](https://github.com/mininet-sec/mininet-sec)**
> (plataforma de emulação para cybersecurity em redes programáveis; tag
> [1.2.0](https://github.com/mininet-sec/mininet-sec/tree/1.2.0),
> [Zenodo](https://zenodo.org/records/22124731)). Também inspirado no repositório
> acadêmico [`Mdp11/mn_security`](https://github.com/Mdp11/mn_security). Reescrito
> do zero em Python 3, com a lógica de detecção separada e testável. Ver
> `RELATED.md` e `.zenodo.json` para os trabalhos relacionados.

## A ideia central

Os detectores são **funções puras sobre eventos de rede normalizados**:

```
detect_xxx(events: list[dict], cfg: dict) -> list[Finding]
```

Isso dá duas coisas de uma vez:

1. **Testabilidade em qualquer lugar** — a suíte `pytest` valida TP/FP com
   traces sintéticos, sem root nem Mininet (roda em CI/nuvem).
2. **Reuso no Mininet** — no modo real, os mesmos detectores recebem eventos
   vindos de captura real (`scapy`), na porta espelho do switch.

O detector é a **única fonte de verdade**; o modo (sim ou real) só muda de onde
vêm os eventos.

## Matriz de cenários

| Case | Cenário | Técnica (ATT&CK) | Sinal de detecção |
|------|---------|------------------|-------------------|
| C1 | ARP spoofing / MITM | T1557.002 | Conflito de binding IP↔MAC (IP com >1 MAC; pior se for o gateway) |
| C2 | Rogue DHCP (MITM) | T1557 | Servidor DHCP fora da allowlist; gateway/DNS forjados |
| C3 | SYN flood / DDoS | T1499 / T1498 | Pico de SYN/s em janela + alta fração half-open; nº de origens |
| C4 | Port scan | T1046 | Uma origem → muitas portas (vertical) ou muitos alvos (horizontal) |
| C5 | SSH brute force | T1110.001 | Rajada de falhas de uma origem em janela; sucesso após o surto |
| C6 | DNS spoofing | T1557 | Respostas conflitantes para o mesmo nome; IP fora do esperado |

### Camada OT/ICS (`lib/ot/`)

Mesma arquitetura (detector puro → finding → evidência), com semântica
industrial: Modbus, OPC UA, estado de processo, lógica de PLC, alarmes. Cada
case aponta uma técnica do **MITRE ATT&CK for ICS**. Detalhes e roadmap em
`docs/OT-ROADMAP.md`.

| Case | Cenário | ATT&CK ICS | Sinal de detecção |
|------|---------|------------|-------------------|
| S1 / C7 | Reconhecimento de ativos OT | T0846 | 1 origem tocando muitos ativos/portas/FCs |
| S2 / C8 | Escrita Modbus não autorizada | T0836/T0831 | write de origem fora da allowlist / objeto crítico (delta físico) |
| S4 / C9 | Rogue master / rogue EWS | T0848 | master fora da allowlist emitindo comando |
| S8 / C10 | DoS contra serviço de controle | T0814 | taxa alta na porta 502/2404/4840 + polls falhando |
| S6 / C11 | OPC UA anônima/insegura | T0836/T0859 | write aceito com auth anônima / security None |
| S9 / C12 | Perda/Manipulação de visão | T0815 | HMI diverge do processo / telemetria obsoleta |

Os cases OT validam-se em **modo sim** e **pytest** (sem root). O **modo real**
no Mininet usa `lib/ot/topology.py` (célula `otcell`), `services/` (Modbus/OPC UA)
e `tools/` (ataque no sandbox); a extração protocol-aware do pcap (Zeek/ICSNPP)
é o próximo passo — ver `docs/OT-ROADMAP.md`. Deps opcionais em `requirements-ot.txt`.

## Instalação

Núcleo + testes (qualquer SO com Python 3.10+):

```bash
pip install pytest          # para a suíte
pip install scapy           # opcional, só para ler pcap no modo real
```

Modo real exige **Linux + root + Mininet**:

```bash
sudo apt install mininet tcpdump
# ferramentas de ataque usadas nos attack_cmd de referência:
sudo apt install dsniff hping3 nmap hydra dnsmasq
```

Modo **Mininet-Sec nativo** (recomendado — usa `NetworkTAP` + captura embutida):

```bash
# via Docker (mais fácil):
docker pull hackinsdn/mininet-sec
docker run --rm -it --privileged -v /lib/modules:/lib/modules \
  hackinsdn/mininet-sec /bin/bash
# ou instalação por fonte: ver https://github.com/mininet-sec/mininet-sec
```

## Manual e lançadores

- **Manual ilustrado:** `docs/manual.html` — guia completo (instalação por SO em
  abas, uso guiado com saídas anotadas, diagramas, glossário, seção técnica).
- **Lançadores de dois cliques:** `launchers/run-linux.sh` (Linux/macOS),
  `launchers/run-windows.bat` (Windows) — rodam pytest + os 6 cases em modo sim.

## Modo sim (padrão — sem root)

```bash
python3 cases/runner.py                     # todos os cases
python3 cases/runner.py --case case03_syn_flood
python3 -m pytest tests/ -v                 # suíte de detecção
```

Saídas em `out/`: uma evidência selada por case + `runner_summary.json`.
Verifique a integridade de uma evidência:

```python
from lib.evidence import Evidence
Evidence.verify("out/case01_arp_spoof.json")   # True se íntegra
```

## Modo real (Linux + root + Mininet)

```bash
sudo python3 cases/runner.py --real
```

Para cada case, o harness (`cases/_harness.py::_run_real`):

1. sobe a topologia `lib/topo.py::build_lab()` com porta-espelho (SPAN) no host
   `sensor`;
2. gera tráfego benigno (baseline);
3. inicia `tcpdump` no sensor;
4. executa o `attack_cmd` do case **no namespace do atacante** (isolado);
5. encerra a captura, normaliza o pcap (`lib/sensor.py`) e roda o detector.

O `attack_cmd` de cada case está documentado no cabeçalho do respectivo arquivo
em `cases/` (ex.: `arpspoof`, `hping3 -S --flood`, `nmap -sS`, `hydra`).

### Modo Mininet-Sec nativo

```bash
sudo python3 cases/runner.py --mnsec
```

Usa `lib/topo_mnsec.py`, que constrói a topologia com a API real do
Mininet-Sec: `Mininet_sec`, `NetworkTAP` (TAP de software que espelha o enlace
para o `sensor`) e `AppManager` (serviços no `server`). A captura vem do
`captureDir` embutido do Mininet-Sec; o pcap é normalizado por `lib/sensor.py`
e processado pelo mesmo detector. Alinhado aos exemplos `firewall.py` e
`sbseg2024.py` do Mininet-Sec 1.2.0.

## Topologia do lab

```
 victim 10.0.0.10 ─┐
gateway 10.0.0.1 ──┤
 server 10.0.0.20 ─┼── s1 ──[mirror SPAN]── sensor 10.0.0.99  (ponto de coleta)
attacker 10.0.0.66 ┘
```

Veja `docs/lab-architecture.html` para o diagrama isométrico com o fluxo
sensor → detector → evidência.

## Esquema dos eventos normalizados

Documentado em `docs/EVENTOS.md`. Resumo: `arp`, `dhcp`, `tcp`, `dns`, `auth` —
cada um um dict com `type`, campos próprios e `ts` (float, segundos).

## Estrutura

```
mininet-sec-lab/
├── COMECE-AQUI.md
├── README.md
├── lib/           # detectores, sensor, evidência, topo, traces
├── cases/         # 6 cases + harness + runner
├── tests/         # pytest dos detectores
├── docs/          # figura da arquitetura + esquema de eventos
└── out/           # evidências e relatórios (gerado)
```

## Como estender

Novo case = novo detector (função pura em `lib/detectors.py`, registrada em
`DETECTORS`) + um trace sintético em `lib/traces.py` + um `CaseSpec` em
`cases/`. Adicione o teste TP/FP em `tests/`. Rode `pytest` e `runner.py`.

## Licença e citação

MIT (ver `LICENSE`). Para citar, ver `CITATION.cff`.
