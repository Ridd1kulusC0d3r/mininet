# Catálogo de cenários — mininet-sec-lab

**50 cenários-template** (15 IT + 35 OT) que o gerador expande em **2668 cases concretos** (`cases/generated/cases.jsonl`), cada um mapeado ao MITRE ATT&CK (ICS v20 / Enterprise) e validado por detector.

## Como funciona

```
cenário-template  ×  grade de parâmetros  →  N cases (JSONL)
      │                      │                        │
  detector + técnica    origem/objeto/valor/      scenario.build(params)
  ATT&CK + severidade   taxa/timing/janela        → eventos → detector
```

- Gerar:   `python3 cases/generate.py`
- Validar tudo: `python3 cases/validate_generated.py` → `out/generated_report.json`
- Pytest (amostra): `python3 -m pytest tests/test_generated.py`

## Cobertura MITRE ATT&CK

| Técnica | Nome | Cenários |
|---|---|---|
| T0814 | Denial of Service | 5 |
| T0816 | T0816 | 1 |
| T0830 | Adversary-in-the-Middle | 4 |
| T0836 | Modify Parameter | 7 |
| T0843 | T0843 | 1 |
| T0846 | Remote System Discovery | 6 |
| T0848 | Rogue Master | 4 |
| T0858 | T0858 | 1 |
| T0859 | Valid Accounts | 6 |
| T0869 | Standard Application Layer Protocol | 1 |
| T0881 | T0881 | 1 |
| T0888 | T0888 | 4 |
| T1692.001 | T1692.001 | 6 |
| T1692.002 | T1692.002 | 3 |

## Os 50 cenários

| # | ID | Camada | Proto | Técnica | Detector | Sev. mín. | Cases |
|---|---|---|---|---|---|---|---|
| 1 | `it_arp_spoof_gateway` | it | ip | T0830 | arp_spoof | critical | 2 |
| 2 | `it_arp_spoof_host` | it | ip | T0830 | arp_spoof | high | 2 |
| 3 | `it_rogue_dhcp` | it | ip | T0830 | rogue_dhcp | critical | 2 |
| 4 | `it_syn_flood_single` | it | ip | T0814 | syn_flood | high | 6 |
| 5 | `it_syn_flood_ddos` | it | ip | T0814 | syn_flood | critical | 4 |
| 6 | `it_port_scan_vertical` | it | ip | T0846 | port_scan | medium | 3 |
| 7 | `it_port_scan_horizontal` | it | ip | T0846 | port_scan | medium | 6 |
| 8 | `it_bruteforce_ssh` | it | ip | T0859 | ssh_bruteforce | high | 2 |
| 9 | `it_bruteforce_ssh_success` | it | ip | T0859 | ssh_bruteforce | critical | 1 |
| 10 | `it_bruteforce_telnet` | it | ip | T0859 | ssh_bruteforce | high | 2 |
| 11 | `it_bruteforce_rdp` | it | ip | T0859 | ssh_bruteforce | high | 2 |
| 12 | `it_bruteforce_smb` | it | ip | T0859 | ssh_bruteforce | high | 2 |
| 13 | `it_bruteforce_ftp` | it | ip | T0859 | ssh_bruteforce | high | 2 |
| 14 | `it_dns_spoof` | it | ip | T0830 | dns_spoof | high | 6 |
| 15 | `it_dns_spoof_exfil` | it | ip | T0869 | dns_spoof | high | 2 |
| 16 | `ot_modbus_unauth_write` | ot | modbus | T0836 | unauth_write | high | 320 |
| 17 | `ot_modbus_out_of_range_write` | ot | modbus | T0836 | out_of_range_write | high | 192 |
| 18 | `ot_modbus_func_violation` | ot | modbus | T1692.001 | func_violation | medium | 32 |
| 19 | `ot_modbus_flood_dos` | ot | modbus | T0814 | flood_dos | critical | 16 |
| 20 | `ot_modbus_recon_sweep` | ot | modbus | T0846 | recon_sweep | medium | 20 |
| 21 | `ot_modbus_fingerprint` | ot | modbus | T0888 | fingerprint | low | 16 |
| 22 | `ot_modbus_broadcast_command` | ot | modbus | T1692.001 | broadcast_command | high | 40 |
| 23 | `ot_modbus_response_without_request` | ot | modbus | T1692.002 | response_without_request | high | 48 |
| 24 | `ot_modbus_rogue_master` | ot | modbus | T0848 | rogue_master | critical | 40 |
| 25 | `ot_dnp3_unauth_write` | ot | dnp3 | T0836 | unauth_write | high | 320 |
| 26 | `ot_dnp3_out_of_range_write` | ot | dnp3 | T0836 | out_of_range_write | high | 192 |
| 27 | `ot_dnp3_func_violation` | ot | dnp3 | T1692.001 | func_violation | medium | 32 |
| 28 | `ot_dnp3_flood_dos` | ot | dnp3 | T0814 | flood_dos | critical | 16 |
| 29 | `ot_dnp3_recon_sweep` | ot | dnp3 | T0846 | recon_sweep | medium | 20 |
| 30 | `ot_dnp3_restart` | ot | dnp3 | T0816 | restart | high | 16 |
| 31 | `ot_dnp3_response_without_request` | ot | dnp3 | T1692.002 | response_without_request | high | 48 |
| 32 | `ot_dnp3_rogue_master` | ot | dnp3 | T0848 | rogue_master | critical | 40 |
| 33 | `ot_dnp3_fingerprint` | ot | dnp3 | T0888 | fingerprint | low | 16 |
| 34 | `ot_s7comm_unauth_write` | ot | s7comm | T0836 | unauth_write | high | 320 |
| 35 | `ot_s7comm_func_violation` | ot | s7comm | T1692.001 | func_violation | medium | 32 |
| 36 | `ot_s7comm_stop` | ot | s7comm | T0881 | stop | critical | 16 |
| 37 | `ot_s7comm_program_download` | ot | s7comm | T0843 | program_download | critical | 16 |
| 38 | `ot_s7comm_mode_change` | ot | s7comm | T0858 | mode_change | high | 16 |
| 39 | `ot_s7comm_recon_sweep` | ot | s7comm | T0846 | recon_sweep | medium | 20 |
| 40 | `ot_s7comm_rogue_master` | ot | s7comm | T0848 | rogue_master | critical | 40 |
| 41 | `ot_s7comm_fingerprint` | ot | s7comm | T0888 | fingerprint | low | 16 |
| 42 | `ot_iec104_unauth_write` | ot | iec104 | T0836 | unauth_write | high | 320 |
| 43 | `ot_iec104_out_of_range_write` | ot | iec104 | T0836 | out_of_range_write | high | 192 |
| 44 | `ot_iec104_func_violation` | ot | iec104 | T1692.001 | func_violation | medium | 32 |
| 45 | `ot_iec104_flood_dos` | ot | iec104 | T0814 | flood_dos | critical | 16 |
| 46 | `ot_iec104_broadcast_command` | ot | iec104 | T1692.001 | broadcast_command | high | 40 |
| 47 | `ot_iec104_recon_sweep` | ot | iec104 | T0846 | recon_sweep | medium | 20 |
| 48 | `ot_iec104_response_without_request` | ot | iec104 | T1692.002 | response_without_request | high | 48 |
| 49 | `ot_iec104_rogue_master` | ot | iec104 | T0848 | rogue_master | critical | 40 |
| 50 | `ot_iec104_fingerprint` | ot | iec104 | T0888 | fingerprint | low | 16 |

## Estender

Novo cenário = acrescentar uma entrada em `scenarios/catalog.py` (`_IT_SPECS` ou `_OT_BY_PROTO` + grade em `_OT_GRID`). O detector pode ser um já existente (`lib/detectors.py` ou `lib/ot/generic.py`) ou um novo. Rode `generate.py` + `validate_generated.py`; o pytest pega automaticamente.
