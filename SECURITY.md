# Política de Segurança

## Versões suportadas

| Versão | Suporte |
|---|---|
| 1.1.x | ✅ correções de segurança |
| 1.0.x | ❌ atualize para 1.1 (inclui correções de log injection e do cálculo da nota) |

## Como reportar uma vulnerabilidade

Não abra uma *issue* pública. Use o recurso **"Report a vulnerability"** da aba *Security* do repositório (GitHub Private Vulnerability Reporting) ou escreva para `seu-email@exemplo.com` com:

1. descrição e impacto;
2. passos para reproduzir (idealmente um log/arquivo mínimo);
3. versão afetada.

Compromisso: confirmação em até 7 dias e correção ou plano de mitigação em até 30 dias.

## Escopo

Dentro do escopo: falhas nos parsers (injeção, ReDoS, DoS), na verificação de assinatura/hash, no tratamento de chaves e na validação de entrada de rede.
Fora do escopo: resultados de detecção "incompletos" (falsos negativos documentados em *Limitações*), e uso da ferramenta contra sistemas sem autorização.

## Uso responsável

O SecFund é uma ferramenta **defensiva**. As funções de rede (`headers --url`, `tls`) só devem ser executadas contra ativos próprios ou com autorização por escrito.
