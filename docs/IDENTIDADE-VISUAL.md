# MININET // SEC LAB — Sistema de identidade visual v3

> **Emulação primeiro. Observabilidade como linguagem visual. Evidência como critério de confiança.**

## Posicionamento

Projeto de pesquisa independente em emulação de redes IT/OT e engenharia de detecção. A interface é uma **bancada visual de investigação de eventos sintéticos**, não um produto comercial de inventário industrial, SIEM, EDR, scanner nem console de monitoramento ao vivo.

A ideia da Claroty é utilizada **somente como referência conceitual de UX industrial**: organização de dispositivos, contexto de ativos, visualização de zonas e comunicações, clareza de risco e priorização contextual. Nada de copiar logotipos, capturas de tela, componentes, marca ou reivindicar associação.

Fontes da referência conceitual:
- https://claroty.com/industrial-cybersecurity/xdome
- https://claroty.com/platform/exposure-management
- https://claroty.com/blog/q-and-a-claroty-xdome-and-the-extended-internet-of-things-xiot

## Identidade

**Marca de apresentação:** `MININET // SEC LAB`  
**Descriptor:** `INDUSTRIAL EMULATION WORKBENCH`  
**Assinatura:** `EMULATE • OBSERVE • DETECT • VERIFY`

Não substituir a referência ao projeto oficial **Mininet** ou ao **Mininet-Sec**. O repositório é um complemento independente, não uma distribuição oficial.

### Tokens

| Papel | Token CSS | Cor |
|---|---|---|
| Fundo | `--bg` | `#070E16` |
| Painel | `--panel` | `#0D1722` |
| Painel elevado | `--panel2` | `#101D29` |
| Divisores | `--line` | `#273949` |
| Texto | `--white` | `#EDF4F7` |
| Texto secundário | `--muted` | `#9CB2C1` |
| Observação, seleção | `--cyan` | `#65EAD9` |
| Alerta, atenção editorial | `--amber` | `#FFA76D` |
| Contexto IT (uso secundário) | `--violet` | `#AD9BF8` |
| Divergência | `--red` | `#FF8A86` |

### Uso consistente

- **Tipografia:** fontes do sistema, títulos grandes e densos, métricas/códigos em fonte monoespaçada. Sem dependência de CDN.
- **Imagens:** SVG autoral, grades topológicas, linhas de telemetria esquemática, placas de instrumentação e chips com texto.
- **Destaque:** ciano para seleção/observação; cobre para laboratório isolado ou atenção. Não utilizar somente a cor como forma de transmitir estado.
- **Layouts:** cabeçalho compacto, cartões utilitários, grandes diagramas, painel lateral de contexto e sumário de evidências.
- **Acessibilidade:** foco por teclado, `aria-pressed`, `aria-live`, `alt`, textos legíveis e suporte a `prefers-reduced-motion`.
- **Sem métricas fictícias apresentadas como reais:** qualquer número do modo sim leva indicação de `snapshot`, fonte e limitações.

## Ativos versionados

| Arquivo | Uso |
|---|---|
| `docs/index.html` | Portal interativo estático, sem chamadas a sistemas OT |
| `docs/assets/mininet-hero.svg` | Ilustração da célula OT no portal |
| `docs/assets/mininet-banner.svg` | Capa de largura total para README |
| `docs/manual.html` | Manual original, com refinamento de paleta e contagem |

## Interação e fontes de dados

A versão inicial do portal apresenta **dois diagramas didáticos** alinhados às topologias do repositório: `lib/topo.py` (IT) e `lib/ot/topology.py` (OT). Os cartões são associados aos **12 casos** versionados e aos resultados guardados em `out/runner_summary.json` (`sim`, 12/12 PASS no snapshot). Valores exibidos estão incorporados à página como fotografia documental. **Não** há coleta automática, varredura de ativos, simulação física, integração com sensores ou execução de comandos no navegador.

Quando o snapshot mudar, revisar manualmente a página ou futuramente integrar um pipeline de publicação de dados sanitizados. Não prometer atualização automática enquanto essa integração não existir.

## GitHub Pages

O site em `docs/index.html` pode ser publicado a partir da pasta `/docs` da branch principal (Settings → Pages → Deploy from a branch). A existência da página HTML no git **não comprova** que GitHub Pages está ativo. O site também pode ser aberto como arquivo local no navegador, sem servidor e sem conexão à rede.

## Evolução desejada, não implementada

- Exportação automatizada de resultados sintéticos com schema validado, nunca dados sensíveis de planta.
- Diagrama derivado de manifesto declarativo de topologia para evitar divergência entre UI e código.
- Facetas por protocolo, modalidade e qualidade da evidência.
- Relatórios comparativos de detecção com precisão/recall em datasets autorizados e com metodologia reprodutível.
- Storytelling guiado por hipótese → evento → detector → evidência → limitação.

## Direitos e limites

Projeto independente; **nenhuma afiliação com Claroty, Mininet ou Mininet-Sec**. Usar o trabalho de terceiros como referência citada, jamais reproduzir assets comerciais ou insinuar equivalência funcional.