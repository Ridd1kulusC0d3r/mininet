# Esquema dos eventos normalizados

Todo detector consome uma lista de dicts. Campo discriminador: `type`.
`ts` é float em segundos (epoch no modo real; relativo nos traces sintéticos).

## arp
```json
{"type":"arp","op":"request|reply","sender_ip":"10.0.0.1",
 "sender_mac":"00:..:01","target_ip":"10.0.0.10","ts":100.0}
```

## dhcp
```json
{"type":"dhcp","msg":"discover|offer|request|ack|nak","server_ip":"10.0.0.1",
 "server_mac":"00:..:01","offered_ip":"10.0.0.10","gateway":"10.0.0.1",
 "dns":"10.0.0.1","ts":100.0}
```

## tcp
```json
{"type":"tcp","src_ip":"10.0.0.66","src_port":50000,"dst_ip":"10.0.0.20",
 "dst_port":80,"flags":"S","ts":100.0}
```
`flags`: letras de `S A R F P U` (ex.: `"S"`, `"SA"`, `"R"`).

## dns
```json
{"type":"dns","qr":"query|response","qname":"banco.example.com",
 "answers":["200.147.100.10"],"src_ip":"10.0.0.1","dst_ip":"10.0.0.10","ts":100.0}
```

## auth
```json
{"type":"auth","service":"ssh","src_ip":"10.0.0.66","dst_ip":"10.0.0.20",
 "user":"root","result":"fail|success","ts":100.0}
```

O mapeamento pcap → evento está em `lib/sensor.py::packet_to_event`.

---

# Eventos OT/ICS (camada lib/ot/)

Consumidos pelos detectores de `lib/ot/detectors.py`. Ver `lib/ot/events.py`.

## modbus
```json
{"type":"modbus","ts":100.0,"src":"10.20.0.66","dst":"10.20.0.20",
 "asset_id":"plc1","operation":"write_register","object":"holding:40001",
 "function_code":6,"before":100,"after":900,
 "authorized":false,"maintenance_window":false}
```
`operation` ∈ read_coils, read_registers, write_coil, write_register, write_multiple.

## opcua
```json
{"type":"opcua","ts":100.0,"src":"10.20.0.66","dst":"10.20.0.30",
 "asset_id":"opc1","operation":"write","node":"ns=2;i=7",
 "security_mode":"None","auth":"anonymous","accepted":true}
```
`operation` ∈ connect, browse, read, write ; `security_mode` ∈ None, Sign, SignAndEncrypt ; `auth` ∈ anonymous, user, cert.

## process
```json
{"type":"process","ts":100.0,"asset_id":"plc1","tag":"tank.level",
 "value":58,"displayed":50,"setpoint":60,"poll_latency_ms":20,"failed_poll":false}
```
`value` = verdade do processo ; `displayed` = valor na HMI.

## plc_change
```json
{"type":"plc_change","ts":100.0,"src":"10.20.0.66","dst":"10.20.0.20",
 "asset_id":"plc1","program_hash":"b2…","prev_hash":"a1…",
 "authorized":false,"maintenance_window":false}
```

## alarm
```json
{"type":"alarm","ts":100.0,"asset_id":"plc1","alarm_id":"AH_level",
 "state":"suppressed","threshold":95,"prev_threshold":80}
```
`state` ∈ active, cleared, suppressed, disabled.

## asset
```json
{"type":"asset","ts":100.0,"asset_id":"plc1","ip":"10.20.0.20",
 "role":"PLC","proto":"modbus"}
```
`role` ∈ HMI, EWS, PLC, OPCUA, HISTORIAN, SENSOR, ATTACKER.
