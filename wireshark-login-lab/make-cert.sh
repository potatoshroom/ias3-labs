#!/usr/bin/env bash
# Lab setup: checks prerequisites, offers to install anything missing,
# generates the self-signed certificate, then verifies it with a real
# TLS handshake. Safe to re-run.
#
# macOS / Linux / Git Bash. On plain Windows use make-cert.bat.
set -euo pipefail
cd "$(dirname "$0")"
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "Python 3 not found. Install it from https://python.org/downloads" >&2
  exit 1
fi
exec "$PY" make_cert.py "$@"
