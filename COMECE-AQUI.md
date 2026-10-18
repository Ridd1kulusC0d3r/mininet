# COMECE-AQUI / MININET // SEC LAB

[**Portal visual**](docs/index.html) · [**Manual ilustrado**](docs/manual.html) · [**Célula OT**](docs/OT-ROADMAP.md) · [**Identidade visual**](docs/IDENTIDADE-VISUAL.md)

> O portal funciona como representação interativa de topologias e resultados **sintéticos**; não executa Mininet no navegador e não monitora redes reais.

Uma ação por vez. Não pule etapas.

> 📖 **Manual ilustrado completo:** abra `docs/manual.html` no navegador
> (instalação por SO, uso guiado, diagramas, glossário e resultado dos testes).
> ⚡ **Dois cliques:** `launchers/run-linux.sh` (Linux/macOS) ou
> `launchers/run-windows.bat` (Windows) rodam tudo em modo sim.

## 1. Ver os cases rodando AGORA (sem instalar nada, sem root)

```bash
python3 cases/runner.py
```

Isso executa os 12 cenários em **modo sim** (traces sintéticos) e grava uma
evidência selada por case em `out/`. É a prova de que a lógica de detecção
funciona. Resultado registrado no snapshot versionado: `12/12 PASS` (a execução local pode variar).

➡️ **Faça só isso primeiro.** Depois volte aqui.

---

## 2. Rodar a suíte de testes (a que roda na nuvem/CI)

```bash
python3 -m pytest tests/ -v
```

Valida os detectores disponíveis e seus casos de teste; confira a contagem exibida pelo pytest. Valida verdadeiro-positivo (ataque detectado) e
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
| `cases/`    | Os 12 cases + o runner.                                          |
| `tests/`    | Suíte pytest dos detectores (roda em qualquer lugar).          |
| `out/`      | Saída: evidências seladas e relatórios (gerado ao rodar).      |
| `docs/`     | Figura da arquitetura e esquema dos eventos.                   |
