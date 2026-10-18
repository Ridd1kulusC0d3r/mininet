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
