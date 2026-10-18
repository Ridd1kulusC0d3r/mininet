"""
Esquema de eventos OT normalizados — consumidos pelos detectores de
`lib/ot/detectors.py`. Mesma filosofia da camada IT: um dict por evento, campo
`type` discrimina, `ts` em segundos (float).

Tipos e campos (resumo; exemplos completos em docs/EVENTOS.md):

  modbus    : {type, ts, src, dst, asset_id, operation, object, function_code,
               before, after, authorized, maintenance_window}
      operation ∈ {read_coils, read_registers, write_coil, write_register,
                   write_multiple}
      object: ex. "holding:40001", "coil:00017"
  opcua     : {type, ts, src, dst, asset_id, operation, node, security_mode,
               auth, accepted}
      operation ∈ {connect, browse, read, write}
      security_mode ∈ {None, Sign, SignAndEncrypt} ; auth ∈ {anonymous, user, cert}
  process   : {type, ts, asset_id, tag, value, displayed, setpoint,
               poll_latency_ms, failed_poll}
      `displayed` = valor mostrado na HMI; `value` = verdade do processo.
  plc_change: {type, ts, src, dst, asset_id, program_hash, prev_hash,
               authorized, maintenance_window}
  alarm     : {type, ts, asset_id, alarm_id, state, threshold, prev_threshold}
      state ∈ {active, cleared, suppressed, disabled}
  asset     : {type, ts, asset_id, ip, role, proto}
      role ∈ {HMI, EWS, PLC, OPCUA, HISTORIAN, SENSOR, ATTACKER}

A camada de política (quem pode comandar o quê, janelas de manutenção, objetos
críticos) é declarativa, passada como `cfg` ao detector — nunca IP hardcoded no
código, para a detecção generalizar.
"""

from __future__ import annotations

# portas de controle típicas (para detectores de DoS/recon)
OT_PORTS = {502: "modbus", 20000: "dnp3", 2404: "iec104", 4840: "opcua",
            102: "s7comm", 44818: "ethernet-ip"}

WRITE_OPS = {"write_coil", "write_register", "write_multiple"}
READ_OPS = {"read_coils", "read_registers"}


def is_write(op: str) -> bool:
    return op in WRITE_OPS


def default_policy() -> dict:
    """Política de exemplo usada pelos traces/testes. Em produção vem de YAML."""
    return {
        "allowed_masters": ["10.20.0.10", "10.20.0.11"],  # HMI, EWS legítimos
        "critical_objects": ["holding:40001", "coil:00017"],
        "maintenance_window": False,
    }
