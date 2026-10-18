#!/usr/bin/env bash
# Lançador de dois cliques (Linux/macOS) — mininet-sec-lab
# Roda a suíte pytest e os 6 cases em modo sim (sem root). Não precisa instalar Mininet.
set -e
cd "$(dirname "$0")/.."
echo "============================================"
echo "  mininet-sec-lab — verificação rápida"
echo "============================================"
python3 -m pip install -q pytest 2>/dev/null || true
echo; echo ">> Suíte de detecção (pytest):"
python3 -m pytest tests/ -q || true
echo; echo ">> Cases (modo sim):"
python3 cases/runner.py || true
echo; echo "Evidências seladas em: out/*.json"
echo "Abra docs/manual.html no navegador para o guia completo."
read -p "Pressione ENTER para sair..."
