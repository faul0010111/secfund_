"""Servidores locais (loopback) usados pelos testes de integração. Nada sai da máquina."""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def make_self_signed(directory: Path) -> tuple[Path, Path]:
    """Certificado autoassinado com SAN para localhost/127.0.0.1 (também serve de âncora de confiança)."""
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(  # noqa: S603
        [
            shutil.which("openssl") or "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True, capture_output=True,
    )  # fmt: skip
    return cert, key


@contextmanager
def tls_server(cert: Path, key: Path):
    """Servidor TLS que apenas completa o handshake. Devolve a porta."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()[1]
    finally:
        stop.set()
        thread.join(2)
        sock.close()


@contextmanager
def plain_server(payload: bytes):
    """Servidor TCP que responde lixo (não-TLS) e fecha: simula alvo sem TLS na porta."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                try:
                    conn.recv(1024)
                    conn.sendall(payload)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()[1]
    finally:
        stop.set()
        thread.join(2)
        sock.close()


@contextmanager
def http_server(response_headers: list[tuple[str, str]], range_body: str = ""):
    """HTTP local: HEAD devolve os headers dados; GET /range/<prefixo> devolve ``range_body``."""
    seen: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):  # noqa: N802
            self.send_response(200)
            for k, v in response_headers:
                self.send_header(k, v)
            self.end_headers()

        def do_GET(self):  # noqa: N802
            seen["path"] = self.path
            seen["padding"] = self.headers.get("Add-Padding", "")
            body = range_body.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
