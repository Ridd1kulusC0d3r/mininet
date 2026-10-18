#!/usr/bin/env python3
"""
Servidor OPC UA mínimo (modo real). Opcional: `pip install asyncua`.
Expõe um nó writable para exercitar S6 (anonymous/insecure write).

    python3 services/opcua_server.py --url opc.tcp://10.20.0.30:4840
"""
import argparse, asyncio

async def run(url):
    try:
        from asyncua import Server
    except Exception:
        raise SystemExit("asyncua ausente. Instale: pip install asyncua")
    server = Server()
    await server.init()
    server.set_endpoint(url)
    idx = await server.register_namespace("mininet-sec-lab")
    obj = await server.nodes.objects.add_object(idx, "PLC")
    var = await obj.add_variable(idx, "setpoint", 100)
    await var.set_writable()
    print(f"[opcua] servidor em {url} (nó writable: setpoint)")
    async with server:
        while True:
            await asyncio.sleep(1)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="opc.tcp://0.0.0.0:4840")
    asyncio.run(run(ap.parse_args().url))
