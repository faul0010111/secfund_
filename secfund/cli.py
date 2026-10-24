"""CLI do SecFund. Uso: python -m secfund <comando> ...

Códigos de saída: 0 = limpo | 1 = achados | 2 = achado CRÍTICO | 3 = erro de uso/E-S | 4 = baseline adulterada.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__, fim, headers, logs, passwords, report, tls


def _emit(a: argparse.Namespace, issues: list[report.Issue], text: str) -> int:
    if a.format == "json":
        payload = report.to_json(issues)
    elif a.format == "sarif":
        payload = report.to_sarif(issues)
    else:
        payload = text
    if a.output:
        Path(a.output).write_text(payload + "\n", encoding="utf-8")
        print(f"Relatório salvo em {a.output}", file=sys.stderr)
    else:
        print(payload)
    return report.exit_code(issues, a.fail_on)


def _key(a: argparse.Namespace) -> bytes | None:
    if getattr(a, "key_file", None):
        path = Path(a.key_file)
        if os.name == "posix" and path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            print(f"Aviso: {path} é acessível por outros usuários; use chmod 600.", file=sys.stderr)
        return fim.load_key_file(path)
    env = os.environ.get("SECFUND_KEY")
    return fim.parse_key(env) if env else None


# --- Comandos -------------------------------------------------------------------------------


def cmd_logs(a: argparse.Namespace) -> int:
    path = Path(a.file)
    with path.open(encoding="utf-8", errors="replace") as fh:
        events = logs.parse_log(fh, year=a.year)
    findings = logs.analyze(
        events, a.threshold, timedelta(minutes=a.window), distributed_ips=a.distributed_ips, allowlist=a.allow_ip
    )
    lines = [f"{len(events)} eventos analisados | limiar={a.threshold} falhas/{a.window}min", ""]
    if not findings:
        lines.append("Nenhuma atividade suspeita encontrada.")
    for f in findings:
        lines.append(str(f))
        lines.append(f"    usuários-alvo: {', '.join(f.users[:8])}")
        if len(f.sources) > 1:
            lines.append(f"    origens: {', '.join(f.sources[:8])}")
    if findings:
        lines += [
            "",
            "Recomendações: bloquear origens (fail2ban/firewall), exigir chave SSH, desativar login root e senha.",
        ]
    return _emit(a, logs.to_issues(findings, str(path)), "\n".join(lines))


def cmd_fim(a: argparse.Namespace) -> int:
    if a.action == "keygen":
        if not a.key_file:
            raise ValueError("keygen exige --key-file <destino>")
        fim.generate_key_file(a.key_file)
        print(f"Chave criada em {a.key_file} (guarde FORA do host monitorado).")
        return 0
    if not a.path:
        raise ValueError(f"'fim {a.action}' exige o diretório a monitorar")
    key = _key(a)
    if a.action == "init":
        n = fim.save_baseline(a.path, a.baseline, key, a.exclude)
        mode = "assinada com HMAC-SHA256" if key else "SEM assinatura (use --key-file para detectar adulteração)"
        print(f"Baseline criada: {n} arquivos -> {a.baseline} ({mode})")
        return 0
    diff = fim.verify(a.path, a.baseline, key, a.exclude)
    issues = fim.to_issues(diff, a.path)
    lines = [f"[{i.title.split(':')[0].replace('Arquivo ', '').upper()}] {i.location}" for i in issues]
    lines.append("Integridade OK." if not issues else f"\n{len(issues)} alteração(ões) detectada(s).")
    return _emit(a, issues, "\n".join(lines))


def cmd_password(a: argparse.Namespace) -> int:
    if a.verify:
        pw = a.password or getpass.getpass("Senha: ")
        ok = passwords.verify_password(pw, a.verify)
        print("Senha confere." if ok else "Senha NÃO confere.")
        if ok and passwords.needs_rehash(a.verify, a.algo):
            print("Aviso: hash com algoritmo/parâmetros desatualizados; refaça o hash no próximo login.")
        return 0 if ok else 1

    if a.generate:
        pw = passwords.generate_password(a.length)
        print(f"Senha gerada: {pw}")
    else:
        pw = a.password or getpass.getpass("Senha (não será exibida): ")

    pwned: int | None = None
    if a.pwned_file:
        pwned = passwords.pwned_count_file(pw, a.pwned_file)
    elif a.pwned:
        print("Consultando HIBP via k-anonymity (somente 5 caracteres do SHA-1 saem desta máquina)...")
        pwned = passwords.pwned_count_range(pw, passwords.fetch_range_online)

    r = passwords.audit_password(pw, pwned)
    print(f"Veredito: {r.verdict} | score {r.score}/100 | ~{r.entropy_bits} bits (limite superior)")
    for issue in r.issues:
        print(f" - {issue}")
    if a.hash:
        print(f"\nHash {a.algo} (armazene ISTO, nunca a senha):")
        print(passwords.hash_password(pw, a.algo))
    return 0 if r.verdict != "FRACA" else 1


def cmd_headers(a: argparse.Namespace) -> int:
    if a.json_file:
        hdrs = json.loads(Path(a.json_file).read_text(encoding="utf-8"))
        where = a.json_file
    else:
        hdrs = headers.fetch_headers(a.url)
        where = a.url
    results, pct, letter = headers.analyze_headers(hdrs)
    lines = [f"[{r.status:<7}] {r.header}: {r.detail}" for r in results]
    lines.append(f"\nNota: {letter} ({pct}%)")
    return _emit(a, headers.to_issues(results, where), "\n".join(lines))


def cmd_tls(a: argparse.Namespace) -> int:
    target = urlsplit(a.target if "//" in a.target else f"//{a.target}")
    if not target.hostname:
        raise ValueError("alvo inválido (use host, host:porta ou https://host)")
    info = tls.fetch_tls(target.hostname, target.port or 443, a.timeout)
    issues = tls.evaluate(info)
    expires = info.not_after.date().isoformat() if info.not_after else "n/d"
    lines = [
        f"Alvo:       {info.host}:{info.port}",
        f"Protocolo:  {info.protocol or 'n/d'}",
        f"Cipher:     {info.cipher or 'n/d'} ({info.cipher_bits} bits)",
        f"Certificado: CN={info.subject or 'n/d'} | emissor={info.issuer or 'n/d'} | expira em {expires}",
        f"Cadeia/hostname: {'válidos' if info.verified else 'INVÁLIDOS (' + info.verify_error + ')'}",
        "",
    ]
    lines += [f"[{i.severity}] {i.title}" for i in issues] or ["Nenhum problema encontrado."]
    return _emit(a, issues, "\n".join(lines))


# --- Parser ---------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    out = argparse.ArgumentParser(add_help=False)
    out.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="formato do relatório")
    out.add_argument("--output", "-o", help="grava o relatório neste arquivo")
    out.add_argument(
        "--fail-on", choices=[*report.FAIL_LEVELS, "never"], default="low",
        help="severidade mínima que faz o comando sair com código != 0 (gate de CI)",
    )  # fmt: skip

    p = argparse.ArgumentParser(prog="secfund", description="Toolkit defensivo de fundamentos de cibersegurança.")
    p.add_argument("--version", action="version", version=f"secfund {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("logs", parents=[out], help="Detecta brute force/spraying/ataque distribuído em logs SSH")
    s.add_argument("file")
    s.add_argument("--threshold", type=int, default=5, help="falhas dentro da janela para alertar")
    s.add_argument("--window", type=int, default=5, help="janela em minutos")
    s.add_argument("--distributed-ips", type=int, default=5, help="IPs distintos contra a mesma conta")
    s.add_argument("--allow-ip", action="append", default=[], metavar="CIDR", help="ignora IP/CIDR (repetível)")
    s.add_argument("--year", type=int, default=None, help="ano do log (syslog não traz o ano)")
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("fim", parents=[out], help="Monitor de integridade de arquivos (baseline assinada)")
    s.add_argument("action", choices=["init", "check", "keygen"])
    s.add_argument("path", nargs="?")
    s.add_argument("--baseline", default="baseline.json")
    s.add_argument("--key-file", help="chave HMAC em hex (ou variável SECFUND_KEY); no keygen, o destino")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="ignora arquivos (repetível)")
    s.set_defaults(func=cmd_fim)

    s = sub.add_parser("password", help="Audita, gera, faz hash e verifica senhas")
    s.add_argument("--password", help="(evite: aparece no histórico do shell)")
    s.add_argument("--generate", action="store_true", help="gera senha aleatória segura")
    s.add_argument("--length", type=int, default=20)
    s.add_argument("--hash", action="store_true", help="imprime o hash para armazenamento")
    s.add_argument("--algo", choices=["scrypt", "pbkdf2"], default="scrypt")
    s.add_argument("--verify", metavar="HASH", help="confere a senha contra um hash armazenado")
    s.add_argument("--pwned", action="store_true", help="consulta HIBP (k-anonymity)")
    s.add_argument("--pwned-file", help="checagem offline contra arquivo SHA-1 HASH:CONTAGEM")
    s.set_defaults(func=cmd_password)

    s = sub.add_parser("headers", parents=[out], help="Analisa security headers HTTP")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="apenas sites que você possui/tem autorização")
    g.add_argument("--json-file", help="headers salvos em JSON (offline)")
    s.set_defaults(func=cmd_headers)

    s = sub.add_parser("tls", parents=[out], help="Audita certificado e protocolo TLS de um host")
    s.add_argument("target", help="host, host:porta ou https://host (apenas hosts autorizados)")
    s.add_argument("--timeout", type=float, default=10.0)
    s.set_defaults(func=cmd_tls)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(errors="replace")  # consoles não-UTF-8 não devem derrubar a CLI
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except fim.BaselineError as e:
        print(f"ALERTA DE INTEGRIDADE: {e}", file=sys.stderr)
        return 4
    except (OSError, ValueError) as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
