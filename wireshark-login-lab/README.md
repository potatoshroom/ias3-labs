# Lab: Sniffing Credentials with Wireshark (HTTP vs HTTPS)

Two identical login forms are served side by side — one over **HTTP** (port 8080)
and one over **HTTPS** (port 8443). Students capture both logins in Wireshark and
compare what an attacker on the same network can actually read.

Python 3.8+ standard library only. No pip installs. Works on Windows, macOS
and Linux — OpenSSL is used when present but is not required.

## Files

| File | Purpose |
|---|---|
| `server.py` | Runs both the HTTP and HTTPS login servers in one process |
| `make_cert.py` | Setup: checks prerequisites, installs what's missing, makes the cert |
| `make-cert.sh` | macOS / Linux / Git Bash wrapper for `make_cert.py` |
| `make-cert.bat` | Windows wrapper (double-clickable) |
| `certs/` | `server.crt` + `server.key` (regenerate per machine; do not commit) |

## Instructor setup

**macOS / Linux**

```bash
./make-cert.sh        # setup — safe to re-run
python3 server.py     # prompts for both ports, then binds on 0.0.0.0
```

**Windows** — double-click `make-cert.bat`, or from PowerShell/cmd:

```bat
make-cert.bat
python server.py
```

Setup is cross-platform and needs **nothing but Python 3.8+**. It:

1. Verifies the Python version.
2. Finds OpenSSL, or offers to install it via `winget` / `choco` / `brew` /
   `apt` / `dnf` / `pacman`. If OpenSSL is absent it doesn't matter — the
   certificate is then built **in pure Python from the standard library**, so
   plain Windows with no Git Bash, no WSL and no OpenSSL still works.
3. Checks for Wireshark and offers to install it the same way, with
   platform-specific notes (Npcap loopback support on Windows, the
   `wireshark` group on Linux).
4. Writes `certs/server.crt` + `certs/server.key`.
5. **Self-tests** the result with a real TLS handshake, so a broken certificate
   is caught at setup rather than mid-demo.

```bash
python make_cert.py --check        # report prerequisites, change nothing
python make_cert.py --yes          # accept every install prompt
python make_cert.py --no-install   # report what's missing, never install
python make_cert.py --force        # replace an existing certificate
python make_cert.py --pure-python  # ignore OpenSSL even if present
```

`server.py` also generates the certificate automatically on first run if it is
missing, so `make-cert` is strictly optional — it exists to get the
prerequisites sorted before class.

`server.py` asks which ports to use and presses Enter-to-accept the defaults:

```
Choose the ports for this lab session (Enter accepts the default).
  HTTP  (cleartext) port [8080]:
  HTTPS (encrypted) port [8443]:
```

It re-asks if a port is already taken (naming the process holding it), is
outside 1–65535, is below 1024, or duplicates the other server's port — so a
second lab session on the same machine just picks different numbers instead of
crashing with `Address already in use`.

To skip the prompt:

```bash
python3 server.py -y                              # take 8080 / 8443
python3 server.py --http-port 8000 --https-port 9443
```

Piped or non-interactive runs (no TTY) silently use the defaults, so the script
stays usable from scripts and `systemd`.

The banner prints the LAN URL students should use. If that address differs from
the one `make-cert.sh` embedded (common on a machine with a VPN up), re-run
`./make-cert.sh` — or just accept the browser warning, which is itself a
teachable moment.

### Demo accounts

| Username | Password |
|---|---|
| `student` | `PlainTextPassw0rd!` |
| `admin` | `SuperSecret123` |

Credentials are **not stored**. They are echoed to the page and printed to the
server console, so the class can compare the terminal against the capture.

> The HTTPS site uses a self-signed certificate, so browsers show
> "Your connection is not private." Click **Advanced → Proceed**. Ask the class
> why the warning appears and what a real CA would have changed.

## Student procedure

### Part 1 — Capture the cleartext login

1. Open Wireshark. Choose the interface carrying the traffic:
   - Same machine as the server → **Loopback: lo0** (macOS) / **Loopback** (Windows npcap) / **lo** (Linux)
   - Separate machine → your Wi-Fi or Ethernet interface
2. Set the capture filter before starting: `tcp port 8080 or tcp port 8443`
3. Start the capture.
4. Browse to `http://<server-ip>:8080/`, log in as `student` / `PlainTextPassw0rd!`
5. Stop the capture and apply the display filter:
   ```
   http.request.method == "POST"
   ```
6. Right-click the POST packet → **Follow → TCP Stream**.

**Expected result** — the request body is fully readable:

```
POST /login HTTP/1.1
Host: 10.0.2.15:8080
Content-Type: application/x-www-form-urlencoded

username=student&password=PlainTextPassw0rd!
```

Record: the source/destination IPs and ports, the HTTP method and URI, and the
exact username and password strings as they appear on the wire.

### Part 2 — Capture the encrypted login

1. Start a fresh capture with the same capture filter.
2. Browse to `https://<server-ip>:8443/`, accept the certificate warning, and log
   in as `admin` / `SuperSecret123`.
3. Stop and apply:
   ```
   tls
   ```

**Expected result** — no credentials anywhere. You will see:

- `Client Hello` → `Server Hello` → `Certificate` → key exchange (the handshake)
- Then only `Application Data` records — opaque ciphertext
- Filter `tls.record.content_type == 23` to isolate just the encrypted records

Try `Edit → Find Packet → String → Packet bytes` and search for `SuperSecret123`.
It will not be found in the HTTPS capture, but the same search **will** hit in
the Part 1 capture.

### Part 3 — What still leaks over HTTPS

TLS protects the payload, not the metadata. From the HTTPS capture, identify:

1. The server's **IP address and port** — visible in every packet.
2. The **hostname** in the Client Hello `server_name` (SNI) extension.
   Filter: `tls.handshake.extensions_server_name`
3. The server's **certificate** — click the `Certificate` packet and read the
   subject/issuer/validity. TLS 1.2 sends this in the clear; in TLS 1.3 it is
   encrypted, so note which version was negotiated
   (`tls.handshake.version`).
4. **Traffic size and timing** — the length of each Application Data record.

## Deliverables

1. Screenshot of the Follow-TCP-Stream window showing the cleartext password.
2. Screenshot of the HTTPS capture showing only `Application Data`.
3. Screenshot of a failed byte-string search for the password in the HTTPS capture.
4. A short table comparing what is exposed by each protocol:

   | Field | HTTP | HTTPS |
   |---|---|---|
   | Username / password | | |
   | URL path (`/login`) | | |
   | Server IP and port | | |
   | Hostname (SNI) | | |
   | Response body | | |

## Discussion questions

1. Who, physically, is able to perform the Part 1 capture on a real network —
   and at which points in the path?
2. HTTPS hid the password. Name two things it did **not** hide, and explain why
   each one is still a privacy concern.
3. The browser warned about the certificate and the login worked anyway. What
   attack does that warning exist to prevent, and why does clicking through it
   defeat the protection TLS was meant to give?
4. The server prints the password to its console in both cases. What does that
   tell you about the limits of transport encryption?
5. Why is hashing the password in JavaScript *before* submitting it over HTTP
   not an adequate substitute for TLS?

## Troubleshooting

| Symptom | Fix |
|---|---|
| No packets captured on the same machine | Select the **loopback** interface, not Wi-Fi |
| Wireshark shows no interfaces (Linux) | `sudo dpkg-reconfigure wireshark-common` and add your user to the `wireshark` group |
| Wireshark shows no interfaces (Windows) | Reinstall **Npcap** with loopback support enabled |
| `Address already in use` | Shouldn't happen — the prompt checks first. If it does, the port was claimed between the check and the bind; re-run and pick another |
| `Missing TLS certificate` | Run `./make-cert.sh` (Windows: `make-cert.bat`) |
| Browser force-upgrades to HTTPS on :8080 | Use a private window, or type the full `http://` URL; clear HSTS if needed |
| Students on other machines can't connect | Check the host firewall allows inbound 8080/8443 |
| HTTPS says "site cannot be reached" (no cert warning) | You are on an address the browser can't route to. Use `https://localhost:<port>` on the server machine, or try each address the startup banner lists — a VPN or virtual adapter adds ones the classroom can't reach |
| HTTPS worked once, then stopped | Fixed — the TLS handshake used to run in the accept loop, so a single idle browser preconnect wedged the listener. Make sure you are on the current `server.py` |

## Scope and ethics

Capture only on a network you own or have been authorized to test, and only the
traffic generated by this lab. Intercepting other people's credentials on a
production or campus network is illegal in most jurisdictions and is out of
scope for this activity.
