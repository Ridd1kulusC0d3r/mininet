#!/usr/bin/env python3
"""
Recon OT para o case S1 (modo real, namespace `attacker`). Varre portas OT e
sonda function codes Modbus. Opcional: `pip install pymodbus`.

    python3 tools/ot_recon.py --net 10.20.0.0/24
"""
import argparse, socket

OT_PORTS = [502, 2404, 4840, 20000, 102, 44818]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--net", default="10.20.0.0/24")
    ap.add_argument("--base", default="10.20.0.", help="prefixo /24")
    a = ap.parse_args()
    for h in range(1, 255):
        ip = f"{a.base}{h}"
        for p in OT_PORTS:
            s = socket.socket(); s.settimeout(0.15)
            if s.connect_ex((ip, p)) == 0:
                print(f"aberto {ip}:{p}")
            s.close()

if __name__ == "__main__":
    main()
