#!/usr/bin/env python3
"""
Gera docs/lab-architecture.html — figura isométrica do mininet-sec-lab.
Desenho à mão (stdlib), sombreamento de 4 tons, ordem de pintura por profundidade,
card emoldurado com legenda e leitura. Tema claro/escuro via CSS.
"""
import math

# ---- projeção isométrica ---------------------------------------------------
AZ = math.radians(30)
EL = math.radians(30)
SX, SY = 1.0, 1.0

_BOUNDS = [1e9, 1e9, -1e9, -1e9]  # minx,miny,maxx,maxy

def iso(x, y, z):
    sx = (x - y) * math.cos(AZ)
    sy = (x + y) * math.sin(EL) - z
    px, py = sx * 22, sy * 22
    _BOUNDS[0] = min(_BOUNDS[0], px); _BOUNDS[1] = min(_BOUNDS[1], py)
    _BOUNDS[2] = max(_BOUNDS[2], px); _BOUNDS[3] = max(_BOUNDS[3], py)
    return px, py

def face(pts, cls):
    d = "M" + " L".join(f"{px:.1f},{py:.1f}" for px, py in pts) + " Z"
    return f'<path d="{d}" class="{cls}"/>'

def box(x, y, z, w, d, h, label=None, accent=False):
    """Caixa isométrica: topo + face esquerda + face direita. Devolve (svg, depth)."""
    top = [iso(x, y, z+h), iso(x+w, y, z+h), iso(x+w, y+d, z+h), iso(x, y+d, z+h)]
    left = [iso(x, y+d, z+h), iso(x, y+d, z), iso(x, y, z), iso(x, y, z+h)]
    right = [iso(x+w, y, z+h), iso(x+w, y, z), iso(x+w, y+d, z), iso(x+w, y+d, z+h)]
    p = "a" if accent else ""
    s = (face(left, f"f-left{p}") + face(right, f"f-right{p}")
         + face(top, f"f-top{p}"))
    if label:
        cx, cy = iso(x+w/2, y+d/2, z+h)
        s += (f'<text x="{cx:.1f}" y="{cy+4:.1f}" class="lbl">{label}</text>')
    depth = x + y + z
    return s, depth

def cable(p0, p1, cls="cable"):
    (x0, y0, z0), (x1, y1, z1) = p0, p1
    a, b = iso(*p0), iso(*p1)
    mx = (a[0]+b[0])/2
    return (f'<path d="M{a[0]:.1f},{a[1]:.1f} Q{mx:.1f},{a[1]-10:.1f} '
            f'{b[0]:.1f},{b[1]:.1f}" class="{cls}"/>'
            f'<circle cx="{a[0]:.1f}" cy="{a[1]:.1f}" r="2.3" class="node"/>'
            f'<circle cx="{b[0]:.1f}" cy="{b[1]:.1f}" r="2.3" class="node"/>')

parts = []
# base slab
s, _ = box(-1, -1, -0.6, 16, 12, 0.6)
parts.append((s, -99))

# switch central
sw, dsw = box(6, 4.5, 0, 3, 3, 1.4, "s1", accent=False)
# hosts ao redor (x,y)
hosts = [
    (1.5, 1.0, "gateway", False),
    (1.5, 7.5, "victim", False),
    (11.5, 1.0, "server", False),
    (11.5, 7.5, "attacker", True),
]
host_boxes = []
for hx, hy, name, atk in hosts:
    hb, hd = box(hx, hy, 0, 2.4, 2.4, 1.2, name, accent=atk)
    host_boxes.append((hb, hd, hx+1.2, hy+1.2))

# sensor (elevado, com tap)
sensor, dsen = box(6.2, 9.8, 0, 2.6, 1.8, 1.1, "sensor", accent=False)

# cabos host->switch
cables = []
sw_top = (7.5, 6.0, 1.4)
for hb, hd, cxr, cyr in host_boxes:
    cables.append(cable((cxr, cyr, 1.2), sw_top))
# tap espelho switch->sensor
tap = cable((7.5, 6.0, 1.4), (7.5, 10.7, 1.1), cls="mirror")

# montar por profundidade (pintar fundo->frente)
drawables = [(dsw, sw)] + [(hd, hb) for hb, hd, _, _ in host_boxes] + [(dsen, sensor)]
drawables.sort(key=lambda t: t[0])
body = parts[0][0] + "".join(c for c in cables) + tap
body += "".join(d[1] for d in drawables)

PAD = 28
minx, miny, maxx, maxy = _BOUNDS
W = (maxx - minx) + 2 * PAD
H = (maxy - miny) + 2 * PAD
tx = PAD - minx
ty = PAD - miny
svg = f'''<svg viewBox="0 0 {W:.0f} {H:.0f}" xmlns="http://www.w3.org/2000/svg">
  <g transform="translate({tx:.1f},{ty:.1f})">{body}</g>
</svg>'''

html = f'''<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arquitetura do Lab</title>
<style>
:root{{
  --bg:#f4f1ea; --ink:#2b2b2b; --card:#fbfaf6; --line:#3a3a3a;
  --top:#dcd6c8; --left:#b8b0a0; --right:#9c9484;
  --atop:#ffd27a; --aleft:#e0a94a; --aright:#c08f38;
  --cable:#6b7280; --mirror:#c0392b; --node:#2b2b2b; --muted:#7a7366;
}}
:root:not([data-theme="light"]){{ }}
@media (prefers-color-scheme: dark){{
  :root:not([data-theme="light"]){{
    --bg:#15171b; --ink:#e7e4dc; --card:#1d2026; --line:#aeb4bf;
    --top:#5a6170; --left:#3e434e; --right:#2c303a;
    --atop:#e0a94a; --aleft:#b07e2c; --aright:#7e5a1e;
    --cable:#8b94a3; --mirror:#ff6b5a; --node:#e7e4dc; --muted:#8b93a0;
  }}
}}
:root[data-theme="dark"]{{
  --bg:#15171b; --ink:#e7e4dc; --card:#1d2026; --line:#aeb4bf;
  --top:#5a6170; --left:#3e434e; --right:#2c303a;
  --atop:#e0a94a; --aleft:#b07e2c; --aright:#7e5a1e;
  --cable:#8b94a3; --mirror:#ff6b5a; --node:#e7e4dc; --muted:#8b93a0;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
  font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  display:flex;justify-content:center;padding:24px 16px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;
  max-width:860px;width:100%;padding:18px 20px 22px;
  box-shadow:0 10px 30px rgba(0,0,0,.12)}}
.head{{display:flex;justify-content:space-between;align-items:baseline;gap:12px}}
.fig{{font-weight:700;letter-spacing:.04em;font-size:13px;color:var(--muted)}}
.title{{font-weight:700;font-size:17px;text-align:right}}
svg{{width:100%;height:auto;display:block;margin:6px 0 2px}}
.f-top{{fill:var(--top)}} .f-left{{fill:var(--left)}} .f-right{{fill:var(--right)}}
.f-topa{{fill:var(--atop)}} .f-lefta{{fill:var(--aleft)}} .f-righta{{fill:var(--aright)}}
path[class^="f-"]{{stroke:var(--line);stroke-width:1;stroke-linejoin:round}}
.lbl{{fill:var(--ink);font-size:10.5px;font-weight:600;text-anchor:middle;
  paint-order:stroke;stroke:var(--card);stroke-width:2.4px}}
.cable{{fill:none;stroke:var(--cable);stroke-width:2.2;stroke-linecap:round}}
.mirror{{fill:none;stroke:var(--mirror);stroke-width:2.4;stroke-dasharray:5 4}}
.node{{fill:var(--node)}}
.foot{{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;
  margin-top:8px;font-size:12.5px}}
.legend span{{display:inline-flex;align-items:center;gap:6px;margin-right:14px}}
.sw{{width:12px;height:12px;border-radius:3px;border:1px solid var(--line);
  display:inline-block}}
.pipe{{margin-top:14px;padding-top:12px;border-top:1px dashed var(--line);
  font-size:13px;line-height:1.5}}
.pipe b{{color:var(--ink)}}
.chip{{display:inline-block;padding:2px 8px;border:1px solid var(--line);
  border-radius:999px;font-size:12px;margin:0 2px}}
.readout{{font-variant-numeric:tabular-nums;color:var(--muted);font-size:12px}}
</style></head>
<body>
  <div class="card">
    <div class="head">
      <div class="fig">Fig 1</div>
      <div class="title">mininet-sec-lab — topologia &amp; coleta</div>
    </div>
    {svg}
    <div class="foot">
      <div class="legend">
        <span><i class="sw" style="background:var(--top)"></i>host / switch</span>
        <span><i class="sw" style="background:var(--atop)"></i>atacante</span>
        <span><i class="sw" style="background:var(--cable)"></i>enlace</span>
        <span><i class="sw" style="background:var(--mirror)"></i>espelho (SPAN) → sensor</span>
      </div>
      <div class="readout">6 cases · 6 detectores · evidência selada SHA-256</div>
    </div>
    <div class="pipe">
      <b>Fluxo de detecção:</b>
      <span class="chip">captura no sensor</span> →
      <span class="chip">evento normalizado</span> →
      <span class="chip">detector (função pura)</span> →
      <span class="chip">Finding</span> →
      <span class="chip">Evidence selada</span><br>
      O <b>sensor</b> fica numa porta-espelho do <b>s1</b>: enxerga todo o
      segmento. O ataque do <b>atacante</b> roda isolado no sandbox; o mesmo
      detector que você testa com <code>pytest</code> processa a captura real.
    </div>
  </div>
</body></html>'''

open("docs/lab-architecture.html", "w", encoding="utf-8").write(html)
print("ok -> docs/lab-architecture.html", len(html), "bytes")
