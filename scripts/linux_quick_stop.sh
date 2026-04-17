#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${VPN_PROXY_SERVICE_NAME:-vpn-proxy}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Please run as root"
  exit 1
fi

echo "[INFO] Stopping ${SERVICE_NAME}"
systemctl stop "${SERVICE_NAME}"

if systemctl is-active --quiet "${SERVICE_NAME}"; then
  echo "[WARN] ${SERVICE_NAME} is still active"
  exit 1
fi

echo "[INFO] ${SERVICE_NAME} stopped"
