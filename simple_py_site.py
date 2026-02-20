#!/usr/bin/env python3

import argparse
import http.server
import os
import socketserver
import ssl
import sys
import threading
from typing import Optional, Tuple
from pathlib import Path
from urllib.parse import unquote

README='''
# ---------------------------------------------------------------------------
# Simple Static Site Bootstrap Script
#
# This script:
#   - Ensures ./http/index.html exists
#   - Ensures ./certs exists
#   - Ensures ./downloads exists
#   - Optionally runs HTTP and/or HTTPS servers
#
# Downloads:
#   Place files in ./downloads and download via:
#     http(s)://<host>/downloads/<filename>
#   Directory listing:
#     http(s)://<host>/downloads/
# ---------------------------------------------------------------------------
# RUN MODES
# ---------------------------------------------------------------------------
#
# HTTP on default port 80
#   ./simple_site.py --run-http
#
# HTTPS on default port 443
#   Uses:
#       certs/full_chain.crt
#       certs/private_key.key
#   ./simple_site.py --run-https
#
# Run BOTH HTTP and HTTPS simultaneously
#   ./simple_site.py --run-http --run-https
#
# ---------------------------------------------------------------------------
# NON-DEFAULT PORTS
# ---------------------------------------------------------------------------
#
# HTTP on port 8080
#   ./simple_site.py --run-http --http-port 8080
#
# HTTPS on port 8443
#   ./simple_site.py --run-https --https-port 8443
#
# ---------------------------------------------------------------------------
# SPECIFYING CUSTOM CERTIFICATES
# ---------------------------------------------------------------------------
#
# ./simple_site.py --run-https \
#     --cert /path/to/full_chain.crt \
#     --key /path/to/private_key.key
#
# Notes:
#   - Paths can be relative or absolute.
#   - Quotes are only required if the path contains spaces.
#   - Certificates must be PEM encoded.
#   - private_key.key should be permissioned:
#         chmod 600 private_key.key
#
# ---------------------------------------------------------------------------
# REQUIREMENTS
# ---------------------------------------------------------------------------
#
# - Python 3.x
#
# ---------------------------------------------------------------------------
'''

# ---------- Defaults ----------
WEB_DIR = Path("./http")
INDEX_FILE = WEB_DIR / "index.html"

CERT_DIR = Path("./certs")
DEFAULT_CERT_FILE = CERT_DIR / "full_chain.crt"
DEFAULT_KEY_FILE = CERT_DIR / "private_key.key"

DOWNLOADS_DIR = Path("./downloads")

DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443

INDEX_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Site Online</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
            background-color: #111;
            color: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: #1c1c1c;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 0 25px rgba(0, 0, 0, 0.6);
            text-align: center;
            max-width: 500px;
        }
        h1 { margin-top: 0; color: #4CAF50; }
        .info { margin-top: 20px; font-size: 0.9em; color: #bbb; }
        button {
            margin-top: 25px;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            background: #4CAF50;
            color: white;
            cursor: pointer;
        }
        button:hover { background: #43a047; }
        a { color: #7dd3fc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Service Online</h1>
        <p>The web service is reachable and responding.</p>

        <p>
            Downloads: <a href="/downloads/">/downloads/</a>
        </p>

        <button onclick="location.reload()">Reload</button>

        <div class="info">
            <div><strong>Host:</strong> <span id="host"></span></div>
            <div><strong>Protocol:</strong> <span id="protocol"></span></div>
            <div><strong>Timestamp:</strong> <span id="time"></span></div>
        </div>
    </div>

    <script>
        document.getElementById("host").textContent = window.location.host;
        document.getElementById("protocol").textContent = window.location.protocol;
        document.getElementById("time").textContent = new Date().toLocaleString();
    </script>
</body>
</html>
"""

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def ensure_dir(path: Path) -> None:
    if not path.exists():
        print(f"[+] Creating directory: {path}")
        path.mkdir(parents=True)
    else:
        print(f"[=] Directory exists: {path}")


def ensure_file(path: Path, content: str, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        print(f"[=] File exists (not modifying): {path}")
        return

    action = "Creating" if not path.exists() else "Overwriting"
    print(f"[+] {action} file: {path}")
    path.write_text(content, encoding="utf-8")


def ensure_structure(overwrite: bool) -> None:
    ensure_dir(WEB_DIR)
    ensure_file(INDEX_FILE, INDEX_CONTENT, overwrite=overwrite)

    ensure_dir(CERT_DIR)
    ensure_dir(DOWNLOADS_DIR)


def validate_https_files(cert_path: Path, key_path: Path) -> None:
    if not cert_path.exists() or not key_path.exists():
        print("[!] HTTPS requested but cert/key not found.")
        print(f"    Cert: {cert_path} (exists={cert_path.exists()})")
        print(f"    Key : {key_path} (exists={key_path.exists()})")
        print("")
        print("Place your PEM files in ./certs (or pass --cert/--key), for example:")
        print(f"  - {DEFAULT_CERT_FILE}")
        print(f"  - {DEFAULT_KEY_FILE}")
        raise FileNotFoundError("Missing HTTPS certificate or key")


class RootedHandler(http.server.SimpleHTTPRequestHandler):
    """
    Serve:
      - /... from WEB_DIR
      - /downloads/... from DOWNLOADS_DIR

    Both are "jailed" to their respective directories to avoid ../ traversal.
    """

    # We'll set these at runtime before starting each server thread
    web_root: Path = WEB_DIR.resolve()
    downloads_root: Path = DOWNLOADS_DIR.resolve()

    def translate_path(self, path: str) -> str:
        # Strip query/fragment and URL-decode
        path = path.split("?", 1)[0].split("#", 1)[0]
        path = unquote(path)

        # Route /downloads to DOWNLOADS_DIR, everything else to WEB_DIR
        if path == "/downloads" or path.startswith("/downloads/"):
            rel = path[len("/downloads"):]  # "" or "/file"
            rel = rel.lstrip("/")
            base = self.downloads_root
        else:
            rel = path.lstrip("/")
            base = self.web_root

        candidate = (base / rel).resolve()

        # Jail to base (block traversal)
        try:
            candidate.relative_to(base)
        except ValueError:
            return str(base)  # fall back to base (will 404 or list base)

        return str(candidate)

    def log_message(self, format, *args):
        # Keep default logging format, but you can tweak if desired.
        super().log_message(format, *args)


def serve_http(port: int) -> None:
    handler = RootedHandler
    handler.web_root = WEB_DIR.resolve()
    handler.downloads_root = DOWNLOADS_DIR.resolve()

    with ThreadingTCPServer(("", port), handler) as httpd:
        print(f"[+] HTTP  serving {WEB_DIR} on port {port}")
        print(f"[+] URL: http://0.0.0.0:{port}")
        print(f"[+] Downloads: http://0.0.0.0:{port}/downloads/")
        httpd.serve_forever()


def serve_https(port: int, cert_path: Path, key_path: Path) -> None:
    handler = RootedHandler
    handler.web_root = WEB_DIR.resolve()
    handler.downloads_root = DOWNLOADS_DIR.resolve()

    with ThreadingTCPServer(("", port), handler) as httpd:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"[+] HTTPS serving {WEB_DIR} on port {port}")
        print(f"[+] URL: https://0.0.0.0:{port}")
        print(f"[+] Downloads: https://0.0.0.0:{port}/downloads/")
        httpd.serve_forever()


def main() -> int:
    # Require root privileges (needed for ports 80 / 443)
    if os.name != "nt":  # Only enforce on Unix-like systems
        if os.geteuid() != 0:
            print("[!] This script must be run as root (required for ports 80/443).")
            print("    Re-run using:")
            print("      sudo ./simple_site.py --run-http")
            print("    or:")
            print("      sudo ./simple_site.py --run-https")
            return 1

    p = argparse.ArgumentParser(description="Setup and optionally run a simple static site over HTTP and/or HTTPS.")
    p.add_argument("--overwrite", action="store_true", help="Overwrite existing index.html")
    p.add_argument("--run-http", action="store_true", help="Run HTTP server")
    p.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT, help="HTTP port")
    p.add_argument("--run-https", action="store_true", help="Run HTTPS server")
    p.add_argument("--https-port", type=int, default=DEFAULT_HTTPS_PORT, help="HTTPS port")
    p.add_argument("--cert", type=str, default=None, help="Path to PEM certificate / full chain")
    p.add_argument("--key", type=str, default=None, help="Path to PEM private key")
    args = p.parse_args()

    ensure_structure(overwrite=args.overwrite)

    cert_path = None
    key_path = None

    if args.run_https:
        if args.cert is not None or args.key is not None:
            if not (args.cert and args.key):
                print("[!] If you pass --cert you must also pass --key (and vice versa).")
                return 2
            cert_path = Path(args.cert)
            key_path = Path(args.key)
        else:
            if DEFAULT_CERT_FILE.exists() and DEFAULT_KEY_FILE.exists():
                cert_path = DEFAULT_CERT_FILE
                key_path = DEFAULT_KEY_FILE
            else:
                print("[!] HTTPS requested but no cert/key provided and default files are missing.")
                print("    Expected defaults:")
                print("      - {0}".format(DEFAULT_CERT_FILE))
                print("      - {0}".format(DEFAULT_KEY_FILE))
                print("    Or pass:")
                print("      --cert /path/to/full_chain.crt --key /path/to/private_key.key")
                return 2

        cert_path = cert_path.resolve()
        key_path = key_path.resolve()

        print("[+] HTTPS cert path: {0}".format(cert_path))
        print("[+] HTTPS key  path: {0}".format(key_path))

        try:
            validate_https_files(cert_path, key_path)
        except FileNotFoundError as e:
            print("[!] {0}".format(e))
            return 2

    threads = []

    try:
        if args.run_http:
            t = threading.Thread(target=serve_http, args=(args.http_port,), daemon=True)
            t.start()
            threads.append(t)

        if args.run_https:
            t = threading.Thread(target=serve_https, args=(args.https_port, cert_path, key_path), daemon=True)
            t.start()
            threads.append(t)

        if not threads:
            print("[=] Setup complete (no servers started).")
            print("")
            print(README.rstrip())
            return 0

        for t in threads:
            t.join()

        return 0

    except KeyboardInterrupt:
        print("\n[!] Stopping")
        return 0
    except ssl.SSLError as e:
        print("[!] SSL error: {0}".format(e))
        print("[!] Common causes: wrong file format (not PEM), key doesn't match cert, missing intermediates in full chain.")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
