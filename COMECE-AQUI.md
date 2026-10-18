# COMECE-AQUI

Uma ação por vez. Não pule etapas.

> 📖 **Manual ilustrado completo:** abra `docs/manual.html` no navegador
> (instalação por SO, uso guiado, diagramas, glossário e resultado dos testes).
> ⚡ **Dois cliques:** `launchers/run-linux.sh` (Linux/macOS) ou
> `launchers/run-windows.bat` (Windows) rodam tudo em modo sim.

## 1. Ver os cases rodando AGORA (sem instalar nada, sem root)

```bash
python3 cases/runner.py
```

Isso executa os 6 cenários em **modo sim** (traces sintéticos) e grava uma
evidência selada por case em `out/`. É a prova de que a lógica de detecção
funciona. Esperado: `6/6 PASS`.

➡️ **Faça só isso primeiro.** Depois volte aqui.

---

## 2. Rodar a suíte de testes (a que roda na nuvem/CI)

```bash
python3 -m pytest tests/ -v
```

Esperado: `17 passed`. Valida verdadeiro-positivo (ataque detectado) e
falso-positivo (tráfego benigno não dispara) de cada detector.

➡️ Rodou verde? Siga para o passo 3.

---

## 3. Entender o que você está vendo

Abra `docs/lab-architecture.html` no navegador: a figura mostra a topologia do
lab e o fluxo **sensor → detector → evidência**. Leia a legenda.

➡️ Depois disso, se quiser rodar de verdade no Mininet, vá para o `README.md`,
seção "Modo real".

---

## O que é cada pasta (referência rápida)

| Pasta       | O que é                                                        |
|-------------|----------------------------------------------------------------|
| `lib/`      | Núcleo: detectores (funções puras), sensor, evidência, topo.   |
| `cases/`    | Os 6 cases + o runner.                                          |
| `tests/`    | Suíte pytest dos detectores (roda em qualquer lugar).          |
| `out/`      | Saída: evidências seladas e relatórios (gerado ao rodar).      |
| `docs/`     | Figura da arquitetura e esquema dos eventos.                   |
