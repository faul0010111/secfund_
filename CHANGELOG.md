# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [1.1.0] — 2026-10-18

### Adicionado
- **Módulo `tls`**: validade/cadeia/hostname do certificado, expiração, protocolo e cipher negociados.
- **Relatórios JSON e SARIF 2.1.0** para todos os módulos, `--output` e `--fail-on` (gate de CI).
- `logs`: detecção de **ataque distribuído**, allowlist por CIDR, IPv6, timestamps ISO 8601, `sshd-session`.
- `fim`: **baseline assinada com HMAC-SHA256**, comando `keygen`, `--exclude`, escrita atômica, tolerância a arquivos ilegíveis.
- `password`: hash **scrypt** (padrão), `--verify`, `needs_rehash`, `--generate`, checagem de vazamentos por **k-anonymity** ou arquivo offline, detecção de variações *leetspeak*, normalização Unicode.
- `headers`: análise de **flags de cookies** e `Cross-Origin-Opener-Policy`.
- Empacotamento (`pyproject.toml`, comando `secfund`), CI, CodeQL, Dependabot, Makefile, `py.typed`.
- 126 testes (97% de cobertura), `ruff`, `mypy --strict`, `bandit`.

### Segurança
- `logs`: proteção contra **log injection** (forja de IP e injeção de terminal), descarte de linhas gigantes.
- `fim`: detecção de **remoção de assinatura** (downgrade) e baseline adulterada (exit 4).
- `password`: parâmetros de custo do hash armazenado são validados antes do cálculo (evita DoS).

### Corrigido
- `headers`: a nota variava de denominador conforme o status dos itens, de modo que corrigir um problema podia piorar a nota.
- `headers`: múltiplos `Set-Cookie` eram sobrescritos ao buscar via rede.
- `logs`: um login aceito *antes* das falhas era marcado como comprometimento.

### Alterado
- Formato da baseline do FIM (v2); baselines da 1.0 devem ser recriadas.
- `hash_password` agora aceita `algorithm`; o padrão passou de PBKDF2 para scrypt.

## [1.0.0] — 2026-10-17
- Versão inicial: `logs`, `fim`, `password` e `headers`.
