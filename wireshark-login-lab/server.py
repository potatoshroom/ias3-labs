#!/usr/bin/env python3
"""
Wireshark lab: identical login forms served over HTTP and HTTPS.

Run both servers at once:
    python3 server.py

Defaults: HTTP on :8080, HTTPS on :8443 (TLS cert from certs/).
Nothing is stored -- credentials are only echoed back so students can
compare what they typed against what Wireshark captured on the wire.
"""

import argparse
import html
import http.server
import socket
import ssl
import subprocess
import sys
import threading
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CERT_FILE = BASE_DIR / "certs" / "server.crt"
KEY_FILE = BASE_DIR / "certs" / "server.key"

# Demo accounts. Deliberately obvious strings so they are easy to spot
# in a packet capture ("Follow TCP Stream" / Edit > Find Packet).
USERS = {
    "student": "PlainTextPassw0rd!",
    "admin": "SuperSecret123",
}

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{scheme_upper} Login &mdash; IAS3 Wireshark Lab</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    font: 16px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #eef1f5; color: #14181f; padding: 24px;
  }}
  .card {{
    width: 100%; max-width: 380px; background: #fff; border-radius: 12px;
    padding: 28px; box-shadow: 0 10px 30px rgba(16,24,40,.12);
    border-top: 6px solid {accent};
  }}
  .badge {{
    display: inline-block; font-size: 12px; font-weight: 700; letter-spacing: .06em;
    text-transform: uppercase; color: #fff; background: {accent};
    padding: 4px 10px; border-radius: 999px; margin-bottom: 14px;
  }}
  h1 {{ font-size: 21px; margin: 0 0 4px; }}
  p.sub {{ margin: 0 0 20px; font-size: 14px; color: #5a6472; }}
  label {{ display: block; font-size: 13px; font-weight: 600; margin: 14px 0 6px; }}
  input {{
    width: 100%; padding: 11px 12px; font-size: 15px; border: 1px solid #c8d0da;
    border-radius: 8px; background: #fff; color: #14181f;
  }}
  input:focus {{ outline: 2px solid {accent}; outline-offset: 1px; border-color: {accent}; }}
  button {{
    width: 100%; margin-top: 20px; padding: 12px; font-size: 15px; font-weight: 600;
    color: #fff; background: {accent}; border: 0; border-radius: 8px; cursor: pointer;
  }}
  button:hover {{ filter: brightness(.92); }}
  .msg {{ margin: 0 0 16px; padding: 11px 12px; border-radius: 8px; font-size: 14px; }}
  .ok   {{ background: #e7f6ec; color: #1b5e33; border: 1px solid #b7e2c6; }}
  .fail {{ background: #fdecec; color: #8a1c1c; border: 1px solid #f5c2c2; }}
  .hint {{ margin-top: 20px; padding-top: 14px; border-top: 1px solid #e6eaef;
           font-size: 12.5px; color: #5a6472; }}
  code {{ background: #f1f4f8; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #11151b; color: #e8ecf1; }}
    .card {{ background: #1a2029; box-shadow: none; }}
    input {{ background: #11151b; border-color: #333d4a; color: #e8ecf1; }}
    p.sub, .hint {{ color: #9aa5b3; }}
    code {{ background: #232b36; }}
    .ok   {{ background: #10301c; color: #97e0b0; border-color: #1f5133; }}
    .fail {{ background: #331414; color: #f2a7a7; border-color: #5e2222; }}
    .hint {{ border-top-color: #2a323d; }}
  }}
</style>
</head>
<body>
  <main class="card">
    <span class="badge">{scheme_upper}{lock}</span>
    <h1>Course Portal Login</h1>
    <p class="sub">IAS3 packet-capture lab &mdash; served over <strong>{scheme}</strong> on port {port}.</p>
    {message}
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="off" autocapitalize="none" required>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="off" required>
      <button type="submit">Sign in</button>
    </form>
    <p class="hint">
      Demo accounts: <code>student / PlainTextPassw0rd!</code> &middot;
      <code>admin / SuperSecret123</code><br>
      Credentials are never stored. {capture_hint}
    </p>
  </main>
</body>
</html>
"""


def render(scheme, port, message=""):
    secure = scheme == "https"
    return PAGE.format(
        scheme=scheme,
        scheme_upper=scheme.upper(),
        port=port,
        accent="#1f7a4d" if secure else "#c2410c",
        lock=" · ENCRYPTED" if secure else " · CLEARTEXT",
        message=message,
        capture_hint=(
            "Wireshark sees only TLS Application Data here."
            if secure
            else "Wireshark sees this POST body in plain text."
        ),
    )


class LoginHandler(http.server.BaseHTTPRequestHandler):
    server_version = "IAS3Lab/1.0"
    protocol_version = "HTTP/1.1"
    timeout = 30            # drop idle keep-alive sockets
    scheme = "http"

    def _send(self, body, status=200, content_type="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/login"):
            self._send(render(self.scheme, self.server.server_address[1]))
        elif path == "/favicon.ico":
            self._send("", status=404, content_type="text/plain")
        else:
            self._send("Not Found", status=404, content_type="text/plain")

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/login":
            self._send("Not Found", status=404, content_type="text/plain")
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        fields = urllib.parse.parse_qs(raw)
        username = fields.get("username", [""])[0]
        password = fields.get("password", [""])[0]

        if USERS.get(username) == password and password:
            msg = (
                '<p class="msg ok">Signed in as <strong>{}</strong>. '
                "The password travelled over <strong>{}</strong>.</p>"
            ).format(html.escape(username), self.scheme.upper())
        else:
            msg = (
                '<p class="msg fail">Invalid credentials for '
                "<strong>{}</strong> &mdash; but the attempt was still transmitted.</p>"
            ).format(html.escape(username or "(blank)"))

        # Log to the console so students can compare terminal vs. capture.
        print(
            "[{}] POST /login  username={!r}  password={!r}".format(
                self.scheme.upper(), username, password
            ),
            flush=True,
        )
        self._send(render(self.scheme, self.server.server_address[1], msg))

    def log_message(self, fmt, *args):
        sys.stderr.write(
            "[{}] {} {}\n".format(self.scheme.upper(), self.address_string(), fmt % args)
        )


class HttpsHandler(LoginHandler):
    scheme = "https"


class ThreadedServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class TLSServer(ThreadedServer):
    """HTTPS server that performs the TLS handshake in the worker thread.

    The obvious approach -- wrapping the *listening* socket -- makes accept()
    do the handshake inside the single accept loop. Browsers routinely open
    speculative connections and never send a ClientHello, and any one of those
    then blocks the whole listener ("site cannot be reached"). Accepting a
    plain socket and wrapping it per-connection keeps the loop responsive.
    """

    ssl_context = None
    handshake_timeout = 10

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(self.handshake_timeout)
        return sock, addr

    def finish_request(self, request, client_address):
        try:
            tls = self.ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            # Browser probe, rejected certificate, or plain HTTP sent to the
            # TLS port. Normal in a lab -- log one line, never a traceback.
            sys.stderr.write(
                "[HTTPS] {} handshake failed: {}\n".format(
                    client_address[0], getattr(exc, "reason", exc)
                )
            )
            return
        try:
            tls.settimeout(None)
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tls.close()

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionResetError, BrokenPipeError,
                            socket.timeout)):
            return                      # routine for a browser, not a crash
        super().handle_error(request, client_address)


def lan_ip():
    """Best-effort LAN address, so students can capture on a real NIC."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def local_addresses():
    """Every IPv4 address this host answers on, best candidate first.

    A machine with a VPN up will happily report the tunnel address as its
    "LAN IP" even though nothing on the classroom network can reach it, so
    list them all and let the operator pick the one that works.
    """
    found = []

    def add(ip):
        if ip and ip not in found and not ip.startswith(("127.", "169.254.")):
            found.append(ip)

    add(lan_ip())
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0])
    except socket.gaierror:
        pass

    # Private (RFC 1918) addresses first -- those are the classroom ones.
    def private(ip):
        return ip.startswith(("10.", "192.168.")) or ip.startswith(
            tuple("172.{}.".format(n) for n in range(16, 32))
        )

    found.sort(key=lambda ip: not private(ip))
    return found


def port_free(host, port):
    """True if we can bind host:port right now."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def port_user(port):
    """Describe whatever is holding the port, for a friendlier error."""
    try:
        import subprocess

        out = subprocess.run(
            ["lsof", "-nP", "-iTCP:{}".format(port), "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip().splitlines()
        if len(out) > 1:
            cols = out[1].split()
            return "{} (PID {})".format(cols[0], cols[1])
    except Exception:
        pass
    return "another process"


def prompt_port(label, default, host, taken=()):
    """Ask for a port, re-asking until we get a free, valid, unused one."""
    while True:
        try:
            raw = input("  {} port [{}]: ".format(label, default)).strip()
        except EOFError:
            raw = ""
        if not raw:
            raw = str(default)

        try:
            port = int(raw)
        except ValueError:
            print("    -> '{}' is not a number. Try again.".format(raw))
            continue

        if not 1 <= port <= 65535:
            print("    -> Ports must be between 1 and 65535.")
            continue
        if port < 1024:
            print("    -> Ports below 1024 need root. Pick something higher (e.g. 8080).")
            continue
        if port in taken:
            print("    -> Already used for the other server. Pick a different one.")
            continue
        if not port_free(host, port):
            print("    -> Port {} is in use by {}. Pick another.".format(port, port_user(port)))
            continue

        return port


def main():
    ap = argparse.ArgumentParser(description="HTTP + HTTPS login forms for a Wireshark lab.")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default: 0.0.0.0)")
    ap.add_argument("--http-port", type=int, default=None,
                    help="skip the prompt and use this port for HTTP")
    ap.add_argument("--https-port", type=int, default=None,
                    help="skip the prompt and use this port for HTTPS")
    ap.add_argument("-y", "--defaults", action="store_true",
                    help="accept 8080/8443 without prompting")
    ap.add_argument("--cert", default=str(CERT_FILE))
    ap.add_argument("--key", default=str(KEY_FILE))
    args = ap.parse_args()

    cert, key = Path(args.cert), Path(args.key)
    if not (cert.exists() and key.exists()):
        print("No TLS certificate found - generating one now...")
        gen = BASE_DIR / "make_cert.py"
        if not gen.exists():
            sys.exit("Missing {} - cannot create a certificate.".format(gen))
        rc = subprocess.call([sys.executable, str(gen)])
        if rc != 0 or not (cert.exists() and key.exists()):
            sys.exit("Certificate generation failed. Run: python make_cert.py")
        print()

    http_port, https_port = args.http_port, args.https_port
    interactive = sys.stdin.isatty() and not args.defaults

    if interactive and (http_port is None or https_port is None):
        print("Choose the ports for this lab session (Enter accepts the default).")
        if http_port is None:
            http_port = prompt_port("HTTP  (cleartext)", 8080, args.host)
        if https_port is None:
            https_port = prompt_port("HTTPS (encrypted)", 8443, args.host, taken=(http_port,))
        print()
    else:
        http_port = 8080 if http_port is None else http_port
        https_port = 8443 if https_port is None else https_port

    if http_port == https_port:
        sys.exit("HTTP and HTTPS cannot share port {}.".format(http_port))

    for label, port in (("HTTP", http_port), ("HTTPS", https_port)):
        if not port_free(args.host, port):
            sys.exit(
                "{} port {} is already in use by {}.\n"
                "  Free it, or re-run and choose a different port.".format(
                    label, port, port_user(port)
                )
            )

    http_srv = ThreadedServer((args.host, http_port), LoginHandler)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    https_srv = TLSServer((args.host, https_port), HttpsHandler)
    https_srv.ssl_context = ctx

    print("=" * 62)
    print("  IAS3 Wireshark lab - login forms are up")
    print("=" * 62)
    print("  On this machine (always works):")
    print("    CLEARTEXT  http://localhost:{}/".format(http_port))
    print("    ENCRYPTED  https://localhost:{}/".format(https_port))
    addresses = local_addresses()
    if addresses:
        print("  From another machine - try these in order:")
        for ip in addresses:
            print("    http://{}:{}/   https://{}:{}/".format(ip, http_port, ip, https_port))
        if len(addresses) > 1:
            print("    (more than one interface: a VPN or virtual adapter is up,")
            print("     so not every address above is reachable from the classroom)")
    print("  HTTPS uses a self-signed certificate - expect a browser warning.")
    print("-" * 62)
    print("  Capture filter:  tcp port {} or tcp port {}".format(http_port, https_port))
    print("  Display filter:  http.request.method == \"POST\" || tls.record.content_type == 23")
    print("  Ctrl+C to stop")
    print("=" * 62, flush=True)

    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    try:
        https_srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        http_srv.shutdown()
        https_srv.shutdown()


if __name__ == "__main__":
    main()
