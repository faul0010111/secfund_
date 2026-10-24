# Contribuindo

1. Faça um *fork* e crie um branch por mudança.
2. Instale as ferramentas de desenvolvimento: `make install`.
3. Antes de abrir o PR, rode `make all` (lint, tipos, SAST e testes com cobertura ≥ 90%).
4. Toda correção de segurança deve vir com um **teste que falha sem ela**.

## Regras do projeto

- **Sem dependências de runtime.** Se algo exigir uma, abra uma discussão antes (ver ADR-1).
- **Entrada externa é hostil:** valide, limite tamanhos e nunca use `eval`/`exec`/`shell=True`.
- Mensagens e documentação em português; identificadores de código em inglês.
- Novas regras de detecção precisam de: ID `SF-<MÓDULO>-NNN` em `report.RULES`, técnica MITRE/OWASP, remediação e teste.
