# Decisões de Arquitetura (ADRs)

Registro curto das decisões que moldaram o SecFund: contexto, decisão e consequências.

## ADR-1 — Somente biblioteca padrão (zero dependências de runtime)

**Contexto.** Ferramentas de segurança são alvo de *supply chain attacks*; cada dependência amplia a superfície a auditar.
**Decisão.** Todo o runtime usa apenas a stdlib (`hashlib`, `hmac`, `ssl`, `ipaddress`, `secrets`, `argparse`...). Ferramentas de qualidade ficam em `[dev]`.
**Consequências.** (+) Auditoria trivial, instalação instantânea, nada para o Dependabot atualizar em produção. (−) Sem Argon2id (não está na stdlib) e sem parsing de certificados além do que `ssl` expõe.

## ADR-2 — scrypt como padrão de hash; PBKDF2 como opção

**Contexto.** A OWASP recomenda Argon2id, depois scrypt; PBKDF2 só quando FIPS-140 é exigido.
**Decisão.** `scrypt` (N=2^17, r=8, p=1) por padrão, via `hashlib.scrypt`; `pbkdf2` (≥ 600.000 iterações) disponível. Formato autodescritivo (`scrypt$n$r$p$salt$hash`) e `needs_rehash()` para migrar parâmetros no login.
**Consequências.** (+) Resistência a GPU/ASIC com a stdlib. (−) ~128 MB de memória por hash: o limite de parâmetros na verificação (ADR-4) evita que isso vire vetor de DoS. Quem puder adicionar dependências deve preferir Argon2id.

## ADR-3 — Baseline do FIM assinada por HMAC, com defesa contra downgrade

**Contexto.** Uma baseline em texto puro não protege contra um atacante que já altera arquivos no host: ele recalcula a baseline.
**Decisão.** Assinatura HMAC-SHA256 sobre uma serialização canônica; chave externa (arquivo `0600` ou `SECFUND_KEY`). Se a chave é informada e **não há assinatura**, a verificação falha.
**Consequências.** (+) Adulteração e remoção de assinatura são detectadas (exit 4). (−) A segurança passa a depender da custódia da chave; HMAC (simétrico) exige a chave no verificador. Evolução possível: assinatura assimétrica (Ed25519), que não está na stdlib.

## ADR-4 — Todo dado externo é hostil

**Contexto.** Logs contêm campos controlados pelo atacante; hashes e baselines vêm de armazenamento que pode ser comprometido.
**Decisão.** Parsers ancorados e validados (`ipaddress`, limites de tamanho), sanitização de saída para o terminal, parâmetros de custo de hash limitados *antes* de qualquer cálculo, leitura de rede com limite de bytes e timeout.
**Consequências.** (+) Fecha classes inteiras de bugs (forja de IP, injeção de terminal, DoS por parâmetros). (−) Algumas linhas legítimas muito incomuns podem ser descartadas (documentado).

## ADR-5 — Modelo unificado `Issue` + SARIF como formato de interoperabilidade

**Contexto.** Cada módulo produzia saídas diferentes, difíceis de integrar a CI e a dashboards.
**Decisão.** Todos os módulos convertem seus resultados para `Issue` (regra, severidade, local, técnica MITRE/OWASP, remediação). `report.py` exporta texto, JSON e **SARIF 2.1.0**; `--fail-on` transforma a severidade em código de saída.
**Consequências.** (+) Um único contrato de saída, integração direta com GitHub Code Scanning e pipelines. (−) O SARIF exige um "local" mesmo para achados que não são arquivos (URL, host:porta), então usamos o alvo como URI.

## ADR-6 — Nota dos headers com pesos constantes

**Contexto.** Na versão 1.0 o peso de um item mudava conforme o status (ex.: CSP fraca valia 12, CSP correta 25), então o denominador da nota variava e corrigir um problema podia **piorar** a nota.
**Decisão.** Cada item tem peso máximo fixo; OK vale 100%, FRACO 50%, AUSENTE 0%.
**Consequências.** (+) Nota monotônica, comprovada por `test_grade_is_monotonic`. (−) Notas da 1.0 não são diretamente comparáveis com as da 1.1.
