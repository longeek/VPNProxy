#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${VPN_PROXY_SERVICE_NAME:-vpn-proxy}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Please run as root"
  exit 1
fi

echo "[INFO] Starting ${SERVICE_NAME}"
systemctl daemon-reload
systemctl restart "${SERVICE_NAME}"
systemctl --no-pager --full status "${SERVICE_NAME}" || true
