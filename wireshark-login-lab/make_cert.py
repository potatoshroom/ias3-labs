#!/usr/bin/env python3
"""
Generate the self-signed TLS certificate for the HTTPS lab server.

Cross-platform and dependency-free:
  * if `openssl` is on PATH (macOS, Linux, Git-for-Windows), it is used;
  * otherwise the certificate is built in pure Python from the standard
    library, so plain Windows + python.exe works with nothing installed.

    python3 make_cert.py            # writes certs/server.crt + server.key
    python3 make_cert.py --force    # overwrite an existing certificate
"""

import argparse
import hashlib
import ipaddress
import os
import secrets
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"

COMMON_NAME = "ias3-lab.local"
DNS_NAMES = ["localhost", "ias3-lab.local"]
DAYS = 365

# ---------------------------------------------------------------- helpers


def lan_ip():
    """Best-effort LAN address. Works the same on Windows, macOS and Linux."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def find_openssl():
    """openssl from PATH, or from the usual Git-for-Windows install spots."""
    found = shutil.which("openssl")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    ):
        if Path(candidate).exists():
            return candidate
    return None


def ip_list():
    """All IPv4 addresses worth putting in the SAN, so the certificate stays
    valid whichever interface the machine is reached on."""
    ips = ["127.0.0.1"]

    def add(ip):
        if ip and ip not in ips and not ip.startswith("169.254."):
            ips.append(ip)

    add(lan_ip())
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0])
    except socket.gaierror:
        pass
    return ips


# ------------------------------------------------------- minimal DER/ASN.1


def _len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag, payload):
    return bytes([tag]) + _len(len(payload)) + payload


def der_int(value):
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if body[0] & 0x80:            # keep it positive
        body = b"\x00" + body
    return tlv(0x02, body)


def der_seq(*items):
    return tlv(0x30, b"".join(items))


def der_set(*items):
    return tlv(0x31, b"".join(items))


def der_oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def der_null():
    return b"\x05\x00"


def der_bitstring(data):
    return tlv(0x03, b"\x00" + data)


def der_octet(data):
    return tlv(0x04, data)


def der_bool(value):
    return tlv(0x01, b"\xff" if value else b"\x00")


def der_utctime(dt):
    return tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def der_printable(text):
    return tlv(0x13, text.encode("ascii"))


def rdn(oid, text):
    return der_set(der_seq(der_oid(oid), der_printable(text)))


# --------------------------------------------------------------- RSA (pure)

SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
]


def is_probable_prime(n, rounds=40):
    """Miller-Rabin. pow() is C-backed, so this is fast enough for a lab."""
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits, e):
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if (cand - 1) % e == 0:          # need gcd(e, p-1) == 1
            continue
        if is_probable_prime(cand):
            return cand


def gen_rsa(bits=2048, e=65537):
    half = bits // 2
    while True:
        p = gen_prime(half, e)
        q = gen_prime(half, e)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        return {
            "n": n, "e": e, "d": d, "p": p, "q": q,
            "dp": d % (p - 1), "dq": d % (q - 1), "qinv": pow(q, -1, p),
        }


SHA256_OID = "2.16.840.1.101.3.4.2.1"
RSA_OID = "1.2.840.113549.1.1.1"
SHA256_RSA_OID = "1.2.840.113549.1.1.11"


def rsa_sign(key, message):
    """PKCS#1 v1.5 signature over SHA-256(message)."""
    digest = hashlib.sha256(message).digest()
    digest_info = der_seq(der_seq(der_oid(SHA256_OID), der_null()), der_octet(digest))
    k = (key["n"].bit_length() + 7) // 8
    padding = b"\xff" * (k - len(digest_info) - 3)
    em = b"\x00\x01" + padding + b"\x00" + digest_info
    sig = pow(int.from_bytes(em, "big"), key["d"], key["n"])
    return sig.to_bytes(k, "big")


def pem(label, der_bytes):
    import base64

    b64 = base64.encodebytes(der_bytes).decode("ascii").replace("\n", "")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN {0}-----\n{1}\n-----END {0}-----\n".format(label, "\n".join(lines))


def build_cert(key, cn, dns_names, ips, days):
    pub = der_seq(der_int(key["n"]), der_int(key["e"]))
    spki = der_seq(der_seq(der_oid(RSA_OID), der_null()), der_bitstring(pub))

    name = der_seq(
        rdn("2.5.4.6", "PH"),
        rdn("2.5.4.10", "IAS3 Lab"),
        rdn("2.5.4.3", cn),
    )

    now = datetime.now(timezone.utc) - timedelta(minutes=5)
    validity = der_seq(der_utctime(now), der_utctime(now + timedelta(days=days)))

    # subjectAltName
    general = b""
    for d in dns_names:
        general += tlv(0x82, d.encode("ascii"))
    for ip in ips:
        general += tlv(0x87, ipaddress.ip_address(ip).packed)
    san = der_seq(der_oid("2.5.29.17"), der_octet(der_seq(general)))

    basic = der_seq(der_oid("2.5.29.19"), der_bool(True), der_octet(der_seq()))
    # digitalSignature | keyEncipherment
    ku = der_seq(der_oid("2.5.29.15"), der_bool(True),
                 der_octet(tlv(0x03, b"\x05\xa0")))
    eku = der_seq(der_oid("2.5.29.37"),
                  der_octet(der_seq(der_oid("1.3.6.1.5.5.7.3.1"))))
    skid = der_seq(der_oid("2.5.29.14"),
                   der_octet(der_octet(hashlib.sha1(pub).digest())))

    extensions = tlv(0xA3, der_seq(basic, ku, eku, san, skid))
    sig_alg = der_seq(der_oid(SHA256_RSA_OID), der_null())

    tbs = der_seq(
        tlv(0xA0, der_int(2)),                       # v3
        der_int(secrets.randbits(64) | 1),           # serial
        sig_alg,
        name,                                        # issuer == subject
        validity,
        name,
        spki,
        extensions,
    )
    cert = der_seq(tbs, sig_alg, der_bitstring(rsa_sign(key, tbs)))
    return cert


def private_key_der(key):
    return der_seq(
        der_int(0), der_int(key["n"]), der_int(key["e"]), der_int(key["d"]),
        der_int(key["p"]), der_int(key["q"]), der_int(key["dp"]),
        der_int(key["dq"]), der_int(key["qinv"]),
    )


# ------------------------------------------------------------- generators


def generate_with_openssl(openssl, ips):
    san = ",".join(["DNS:" + d for d in DNS_NAMES] + ["IP:" + i for i in ips])
    cmd = [
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", str(DAYS),
        "-keyout", str(KEY_FILE), "-out", str(CERT_FILE),
        "-subj", "/C=PH/O=IAS3 Lab/CN=" + COMMON_NAME,
        "-addext", "subjectAltName=" + san,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return False, (result.stderr or "").strip()
    return True, "openssl"


def generate_with_python(ips):
    key = gen_rsa(2048)
    cert = build_cert(key, COMMON_NAME, DNS_NAMES, ips, DAYS)
    CERT_FILE.write_text(pem("CERTIFICATE", cert))
    KEY_FILE.write_text(pem("RSA PRIVATE KEY", private_key_der(key)))
    return True, "pure Python"


# ------------------------------------------------- prerequisites / install

PKG_MANAGERS = [
    # (name, probe, install-command builder, needs_sudo)
    ("winget", "winget", lambda pkg: ["winget", "install", "--silent",
                                      "--accept-package-agreements",
                                      "--accept-source-agreements", "-e", "--id", pkg], False),
    ("choco", "choco", lambda pkg: ["choco", "install", "-y", pkg], False),
    ("brew", "brew", lambda pkg: ["brew", "install", pkg], False),
    ("apt", "apt-get", lambda pkg: ["apt-get", "install", "-y", pkg], True),
    ("dnf", "dnf", lambda pkg: ["dnf", "install", "-y", pkg], True),
    ("pacman", "pacman", lambda pkg: ["pacman", "-S", "--noconfirm", pkg], True),
]

# Package ids per manager: (openssl, wireshark)
PKG_NAMES = {
    "winget": ("ShiningLight.OpenSSL.Light", "WiresharkFoundation.Wireshark"),
    "choco": ("openssl", "wireshark"),
    "brew": ("openssl", "--cask wireshark"),
    "apt": ("openssl", "wireshark"),
    "dnf": ("openssl", "wireshark"),
    "pacman": ("openssl", "wireshark-qt"),
}


def detect_pkg_manager():
    for name, probe, builder, sudo in PKG_MANAGERS:
        if shutil.which(probe):
            return {"name": name, "build": builder, "sudo": sudo}
    return None


def find_wireshark():
    """Wireshark GUI or tshark, wherever the platform hides it."""
    for exe in ("wireshark", "tshark", "Wireshark"):
        found = shutil.which(exe)
        if found:
            return found
    candidates = [
        "/Applications/Wireshark.app/Contents/MacOS/Wireshark",
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
        "/usr/bin/wireshark",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def ask(question, assume_yes):
    if assume_yes:
        print("  {} yes (--yes)".format(question))
        return True
    if not sys.stdin.isatty():
        print("  {} skipped (non-interactive)".format(question))
        return False
    try:
        return input("  {} [y/N]: ".format(question)).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def install_package(pm, pkg, label, assume_yes):
    """Install one package through the detected manager. Returns True on success."""
    cmd = pm["build"](pkg)
    # brew casks arrive as a single "--cask wireshark" string
    cmd = [part for item in cmd for part in (item.split() if " " in item else [item])]
    needs_root = pm["sudo"] and hasattr(os, "geteuid") and os.geteuid() != 0
    if needs_root:
        cmd = ["sudo"] + cmd

    print("  Running: {}".format(" ".join(cmd)))
    try:
        rc = subprocess.call(cmd)
    except (OSError, KeyboardInterrupt) as exc:
        print("  Could not run the installer: {}".format(exc))
        return False
    if rc != 0:
        print("  {} install failed (exit {}). Install it manually.".format(label, rc))
        return False
    print("  {} installed.".format(label))
    return True


def check_python():
    """pow(e, -1, m) needs 3.8; f-strings/typing elsewhere assume 3.6+."""
    if sys.version_info < (3, 8):
        print("ERROR: Python 3.8+ required, found {}.{}.{}".format(*sys.version_info[:3]))
        print("       Download a current Python from https://python.org/downloads")
        return False
    print("  Python {}.{}.{} ... OK".format(*sys.version_info[:3]))
    return True


def ensure_prerequisites(assume_yes, allow_install):
    """Check (and optionally install) everything the lab needs. Never fatal
    except for Python itself -- the cert generator has a pure-Python path."""
    print("Checking prerequisites...")
    if not check_python():
        return False

    pm = detect_pkg_manager() if allow_install else None

    openssl = find_openssl()
    if openssl:
        print("  OpenSSL ... found ({})".format(openssl))
    else:
        print("  OpenSSL ... not found (optional - pure-Python fallback will be used)")
        if pm and ask("Install OpenSSL with {}?".format(pm["name"]), assume_yes):
            if install_package(pm, PKG_NAMES[pm["name"]][0], "OpenSSL", assume_yes):
                openssl = find_openssl()

    wireshark = find_wireshark()
    if wireshark:
        print("  Wireshark ... found ({})".format(wireshark))
    else:
        print("  Wireshark ... NOT FOUND - the lab needs it to capture packets")
        if pm and ask("Install Wireshark with {}?".format(pm["name"]), assume_yes):
            if install_package(pm, PKG_NAMES[pm["name"]][1], "Wireshark", assume_yes):
                wireshark = find_wireshark()
        if not wireshark:
            print("     Download it from https://www.wireshark.org/download.html")
            if sys.platform.startswith("linux"):
                print("     Then allow non-root capture:")
                print("       sudo dpkg-reconfigure wireshark-common")
                print("       sudo usermod -aG wireshark $USER   (log out and back in)")
            elif sys.platform == "win32":
                print("     Include Npcap WITH loopback support during setup.")

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    print("  certs/ directory ... OK")
    return True


def self_test():
    """Prove the generated pair really completes a TLS handshake."""
    import ssl
    import threading

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    except Exception as exc:
        print("  Self-test FAILED loading the pair: {}".format(exc))
        return False

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    error = {}

    def serve():
        try:
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(64)
                tls.send(b"ok")
        except Exception as exc:          # noqa: BLE001 - reported below
            error["server"] = exc

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    try:
        client = ssl.create_default_context(cafile=str(CERT_FILE))
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with client.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.send(b"ping")
                tls.recv(8)
                version = tls.version()
        print("  Self-test ... OK (verified handshake, {})".format(version))
        return True
    except Exception as exc:
        print("  Self-test FAILED: {}".format(exc))
        if "server" in error:
            print("    server side: {}".format(error["server"]))
        return False
    finally:
        t.join(timeout=2)
        srv.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true", help="overwrite an existing certificate")
    ap.add_argument("--pure-python", action="store_true",
                    help="skip openssl even if it is installed")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="answer yes to every install prompt")
    ap.add_argument("--no-install", action="store_true",
                    help="only report missing software, never install it")
    ap.add_argument("--check", action="store_true",
                    help="check prerequisites and exit without touching the certificate")
    args = ap.parse_args()

    print("=" * 62)
    print("  IAS3 Wireshark lab - setup")
    print("=" * 62)

    if not ensure_prerequisites(args.yes, allow_install=not args.no_install):
        return 1
    if args.check:
        return 0
    print()

    if CERT_FILE.exists() and KEY_FILE.exists() and not args.force:
        print("Certificate already exists:")
        print("  {}".format(CERT_FILE))
        print("  {}".format(KEY_FILE))
        ok = self_test()
        print("Re-run with --force to replace it.")
        return 0 if ok else 1

    ips = ip_list()
    openssl = None if args.pure_python else find_openssl()
    if openssl:
        ok, how = generate_with_openssl(openssl, ips)
        if not ok:
            print("openssl failed ({}); falling back to pure Python.".format(how))
            ok, how = generate_with_python(ips)
    else:
        print("Generating with pure Python (a few seconds)...")
        ok, how = generate_with_python(ips)

    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass

    print("Certificate created via {}:".format(how))
    print("  {}  (valid {} days)".format(CERT_FILE, DAYS))
    print("  {}".format(KEY_FILE))
    print("  Names: {}".format(", ".join(DNS_NAMES + ips)))
    if not self_test():
        return 1

    print()
    print("Setup complete. Start the lab with:")
    print("  {} server.py".format(Path(sys.executable).name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
