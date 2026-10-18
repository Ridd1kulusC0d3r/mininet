# MININET // SEC LAB — Sistema de identidade visual v4

> **Emulação primeiro. Observabilidade como linguagem visual. Evidência como critério de confiança.**

## Posicionamento

Projeto de pesquisa independente em emulação de redes IT/OT e engenharia de detecção. A interface é uma **bancada visual de investigação de eventos sintéticos**, não um produto comercial de inventário industrial, SIEM, EDR, scanner nem console de monitoramento ao vivo.

A Claroty é utilizada como **referência cromática expressamente solicitada e referência conceitual de UX industrial**: organização de dispositivos, contexto de ativos, visualização de zonas e comunicações, clareza de risco e priorização contextual. Nada de copiar logotipos, capturas de tela, componentes, marca ou reivindicar associação.

Fontes da referência conceitual:
- https://claroty.com/industrial-cybersecurity/xdome
- https://claroty.com/platform/exposure-management
- https://claroty.com/blog/q-and-a-claroty-xdome-and-the-extended-internet-of-things-xiot

## Identidade

**Marca de apresentação:** `MININET // SEC LAB`  
**Descriptor:** `INDUSTRIAL EMULATION WORKBENCH`  
**Assinatura:** `EMULATE • OBSERVE • DETECT • VERIFY`

Não substituir a referência ao projeto oficial **Mininet** ou ao **Mininet-Sec**. O repositório é um complemento independente, não uma distribuição oficial.

### Paleta oficial Claroty 2026: aplicação cromática

Valores abaixo transcritos do **[Claroty Brand Identity Guidelines 2026](https://web-assets.claroty.com/brand-kit/claroty-brand-guide-2026-external.pdf)**, páginas 8–10 (numeração impressa). A referência permite compreender as cores, **não estabelece parceria nem afiliação**. Logotipos, fontes licenciadas, layouts oficiais e identidade nominativa de terceiros **não** são utilizados.

| Papel | Token / utilização no Mininet | HEX | Origem |
|---|---|---|---|
| Magenta corporativo | `--claroty-pink` e `--pink` / ações, seleção | `#E20AB7` | Claroty Pink |
| Roxo corporativo | `--claroty-purple` / faixas e gradientes | `#8815FF` | Claroty Purple |
| Roxo claro de interface | `--purple-soft` / links de atenção, texto | `#BF94FF` | Variação de acessibilidade criada para o projeto |
| Rosa tonal | `--pink-soft` / apoio, contextos | `#D87EB4` | Light Pink |
| Preto / base neutra | fundo base / canvas | `#000000` | Claroty Black |
| Cinza de interface | separações | `#DADADA` | Mid Gray |
| Branco / texto | `--white` | `#F5F5F5` | Light Gray |
| Verde industrial | `--industrial-green` / status e conexão didática | `#7B953B` | Industrial Green |
| Vermelho de contexto | `--critical` | `#CC1F32` | Team82 Red |
| Fundo de interface próprio | `--bg` | `#08060B` | Adaptação neutra do Mininet |
| Painel escuro próprio | `--panel` | `#18111E` | Adaptação do Mininet |
| Divisores próprios | `--line` | `#49344F` | Adaptação do Mininet |

**Hierarquia visual:** preto/cinza + magenta/roxo dominam; gradações roxo/rosa dão profundidade; verde industrial e vermelho de risco são acentos pontuais, não a identidade principal. O guia da Claroty sugere proporções 50% primárias, 40% tons e 10% secundárias. Essa é **uma inspiração cromática**, sem reprodução do sistema gráfico proprietário.

**Contraste:** texto corrente usa tons neutros claros. O magenta oficial `#E20AB7` tem contraste aproximado de 4,7:1 sobre o fundo `#08060B`; o roxo corporativo `#8815FF`, insuficiente como texto pequeno nesse fundo, aparece sobretudo em preenchimentos e gradientes. O `#BF94FF` é uma adaptação de interface para leitura.

### Uso consistente

- **Tipografia:** fontes do sistema, títulos grandes e densos, métricas/códigos em fonte monoespaçada. Sem dependência de CDN.
- **Imagens:** SVG autoral, grades topológicas, linhas de telemetria esquemática, placas de instrumentação e chips com texto.
- **Destaque:** magenta em seleção e chamadas para ação, roxo em painéis/gradientes e verde industrial exclusivamente para status/telemetria ilustrativa. Não utilizar somente a cor como forma de transmitir estado.
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