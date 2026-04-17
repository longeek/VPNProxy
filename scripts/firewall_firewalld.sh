#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-8443}"
PROTO="${2:-tcp}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/firewall_firewalld.sh ${PORT} ${PROTO}"
  exit 1
fi

if ! command -v firewall-cmd >/dev/null 2>&1; then
  echo "firewall-cmd not found. Install firewalld first."
  exit 1
fi

systemctl enable --now firewalld
firewall-cmd --permanent --add-port="${PORT}/${PROTO}"
firewall-cmd --reload
firewall-cmd --list-ports

echo "firewalld rule applied: allow ${PORT}/${PROTO}"
