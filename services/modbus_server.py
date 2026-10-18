#!/usr/bin/env python3
"""
Servidor Modbus/TCP mínimo para o PLC do laboratório (modo real no Mininet).
Opcional: requer `pip install pymodbus`. Em sim/pytest NÃO é usado.

Sobe um datastore com holding registers / coils, simulando um setpoint de nível
de tanque em holding:40001. Rode no namespace do host `plc` (10.20.0.20):

    python3 services/modbus_server.py --host 10.20.0.20 --port 502
"""
import argparse

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=502)
    a = ap.parse_args()
    try:
        from pymodbus.server import StartTcpServer
        from pymodbus.datastore import (ModbusSequentialDataBlock,
                                        ModbusSlaveContext, ModbusServerContext)
    except Exception:
        raise SystemExit("pymodbus ausente. Instale: pip install pymodbus")
    block = ModbusSequentialDataBlock(0, [100] * 200)   # valores iniciais
    store = ModbusSlaveContext(hr=block, co=ModbusSequentialDataBlock(0, [0]*200))
    ctx = ModbusServerContext(slaves=store, single=True)
    print(f"[modbus] PLC ouvindo em {a.host}:{a.port} (holding:40001=100)")
    StartTcpServer(context=ctx, address=(a.host, a.port))

if __name__ == "__main__":
    main()
