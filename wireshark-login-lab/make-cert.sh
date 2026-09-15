#!/usr/bin/env bash
# Generates a self-signed certificate for the HTTPS lab server.
# Browsers will warn -- that is expected and worth discussing in class.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p certs

# Include the machine's LAN IP so students can reach it from other hosts.
LAN_IP="$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1)"
LAN_IP="${LAN_IP:-127.0.0.1}"

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -subj "/C=PH/O=IAS3 Lab/CN=ias3-lab.local" \
  -addext "subjectAltName=DNS:localhost,DNS:ias3-lab.local,IP:127.0.0.1,IP:${LAN_IP}" \
  2>/dev/null

chmod 600 certs/server.key
echo "Certificate created:"
echo "  certs/server.crt  (valid 365 days, SAN: localhost, 127.0.0.1, ${LAN_IP})"
echo "  certs/server.key"
