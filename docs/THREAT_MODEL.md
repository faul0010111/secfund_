# Modelo de Ameaças — SecFund

Metodologia: **STRIDE** por componente, com mitigação adotada, teste que a comprova e risco residual.
Versão do documento: 1.1 (acompanha SecFund 1.1.0).

## 1. Escopo e ativos

| Ativo | Por que importa |
|---|---|
| Servidores com SSH exposto | Ponto de entrada comum de ataques de credencial |
| Arquivos de aplicação/configuração | Alvo de web shells, backdoors e defacement |
| Credenciais de usuários | Comprometimento leva a movimentação lateral |
| Aplicações web e canais TLS | Headers/ciphers fracos ampliam o impacto de XSS, clickjacking e interceptação |
| **A própria ferramenta** (baseline, chave HMAC, relatórios) | Se for adulterada, passa a dar falsa sensação de segurança |

**Fronteiras de confiança:** (1) arquivos de log, baseline e hashes armazenados são **entrada não confiável**; (2) respostas de rede (headers, certificados, API HIBP) são **entrada não confiável**; (3) a chave HMAC e a linha de comando são **confiáveis**.

**Premissa de atacante:** controla o conteúdo de campos do log (ex.: nome de usuário SSH), pode alterar arquivos do host monitorado e tenta esconder o rastro. Não controla a chave HMAC guardada fora do host.

## 2. Ameaças e mitigações

| # | STRIDE | Ameaça | Mitigação | Teste | Residual |
|---|---|---|---|---|---|
| 1 | Spoofing | **Log injection**: nome de usuário `x from 9.9.9.9 port 1` forja o IP atribuído, culpando um inocente | Regex ancoradas no fim; usuário guloso; IP validado com `ipaddress` | `test_username_cannot_forge_source_ip` | Baixo |
| 2 | Tampering | **Injeção de terminal**: ANSI/controle no usuário manipula a tela do analista | Sanitização de não imprimíveis + truncamento | `test_control_characters_are_sanitized` | Baixo |
| 3 | Tampering | Atacante reescreve `baseline.json` após alterar arquivos | Baseline assinada com HMAC-SHA256; chave fora do host | `test_tampered_baseline_detected` | Médio: sem a chave, a baseline não é verificável |
| 4 | Tampering | **Downgrade**: remove a assinatura para evitar a checagem | Chave informada + baseline sem assinatura = falha (exit 4) | `test_signature_stripping_downgrade_rejected` | Baixo |
| 5 | Tampering | Baseline corrompida/formato antigo mascarando mudanças | Validação de versão/estrutura; erro explícito | `test_corrupt_and_old_format_rejected` | Baixo |
| 6 | Info disclosure | Chave HMAC legível por outros usuários | `0600` + `O_EXCL`; aviso na CLI se permissões frouxas | `TestKeys`, `TestKeyPermissionWarning` | Médio: depende da higiene do operador |
| 7 | Info disclosure | Senha no histórico do shell / `ps` | `getpass` por padrão; `--password` documentado como inseguro | — | Médio se o operador ignorar o aviso |
| 8 | Info disclosure | Envio da senha a serviço externo ao checar vazamentos | k-anonymity: só 5 chars do SHA-1; modo 100% offline disponível | `test_k_anonymity_only_sends_five_chars` | Baixo |
| 9 | Info disclosure | Hash fraco permite quebra offline | scrypt (N=2^17) por padrão; PBKDF2 ≥ 600k; salt único; NFKC | `TestHashing` | Baixo |
| 10 | Denial of service | **Hash forjado** com custo absurdo (`n=2^30`, iterações enormes) trava a verificação | Limites de `n`, `r`, `p`, iterações e tamanho do digest antes de calcular | `test_hostile_parameters_rejected_*` | Baixo |
| 11 | Denial of service | Linhas gigantes / log enorme esgotam CPU ou memória | Limite de 2048 chars por linha; leitura em streaming | `test_overlong_line_discarded`, `test_log_file_is_streamed_not_loaded` | Médio: eventos ainda ficam em memória |
| 12 | Denial of service | Resposta HIBP gigante | Leitura limitada a 4 MB; timeout | — | Baixo |
| 13 | Elevation / SSRF | `--url` apontando para `file://` ou esquemas exóticos | Apenas `http`/`https` | `test_rejects_non_http_scheme` | Médio se exposto como serviço (rede interna acessível) |
| 14 | Tampering | Symlink aponta para fora do diretório monitorado | `followlinks=False`; symlinks ignorados | `test_symlinks_are_not_followed` | Baixo |
| 15 | Spoofing | Ataque distribuído lento evita limiares por IP | Detecção por usuário (muitos IPs) | `test_detects_distributed_attack` | Médio: janela fixa; ataques "low and slow" passam |
| 16 | Repudiation | Achados sem trilha / difíceis de integrar | Saída determinística, JSON/SARIF, códigos de saída | `TestExporters` | Baixo |
| 17 | Spoofing | MITM durante a auditoria TLS (cliente aceita certificado inválido) | Validação padrão; a conexão sem validação é só para ler protocolo/cipher e **não envia dados** | `test_self_signed_is_flagged_*` | Baixo |
| 18 | Tampering | Comprometimento do CI / dependências | Zero deps de runtime; permissões mínimas; Dependabot; CodeQL | — | Médio: actions fixadas por tag, não por SHA |

## 3. Cobertura de técnicas (MITRE ATT&CK)

| Técnica | Módulo |
|---|---|
| T1110.001 Password Guessing · T1110.003 Password Spraying | `logs` |
| T1078 Valid Accounts (login aceito após falhas) | `logs` |
| T1565 Data Manipulation · T1505.003 Web Shell (arquivo novo) | `fim` |
| T1070 Indicator Removal (arquivo removido) · T1222 Permissões | `fim` |
| T1557 Adversary-in-the-Middle (HSTS/TLS) | `headers`, `tls` |
| T1189 Drive-by Compromise (mitigado por CSP) | `headers` |

| Framework | Itens |
|---|---|
| OWASP Top 10 2021 | A02 Cryptographic Failures · A05 Security Misconfiguration · A07 Identification & Authentication Failures · A08 Software & Data Integrity Failures |
| NIST SP 800-63B | Comprimento, bloqueio de senhas comuns/vazadas, normalização Unicode, hash lento |
| CIS Controls v8 | 3 (Dados) · 5 (Contas) · 8 (Logs de auditoria) · 16 (Segurança de aplicações) |

## 4. Fora de escopo

Detecção em tempo real, correlação multi-host (SIEM), análise de malware, resposta automática (bloqueio de IP), varredura ativa de ciphers/protocolos e testes de intrusão.
