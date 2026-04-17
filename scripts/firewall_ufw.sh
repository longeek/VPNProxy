#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-8443}"
PROTO="${2:-tcp}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/firewall_ufw.sh ${PORT} ${PROTO}"
  exit 1
fi

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not found. Install first: sudo apt install -y ufw"
  exit 1
fi

ufw allow "${PORT}/${PROTO}"
ufw --force enable
ufw status verbose

echo "UFW rule applied: allow ${PORT}/${PROTO}"
