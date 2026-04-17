#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${VPN_PROXY_SERVICE_NAME:-vpn-proxy}"
SERVER_PORT="${VPN_PROXY_SERVER_PORT:-8443}"
JOURNAL_LINES="${VPN_PROXY_JOURNAL_LINES:-80}"
FOLLOW="no"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/linux_quick_monitor.sh [--follow]

Options:
  --follow    Follow journal logs continuously
  -h, --help  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --follow)
      FOLLOW="yes"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Please run as root"
  exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "[ERROR] rg is required"
  exit 1
fi

echo "== Service Status =="
systemctl --no-pager --full status "${SERVICE_NAME}" || true
echo

echo "== Listen Port (${SERVER_PORT}) =="
if command -v ss >/dev/null 2>&1; then
  ss -lntp | rg "[:.]${SERVER_PORT}\\b" || echo "(not found)"
else
  echo "ss not available"
fi
echo

echo "== Recent Logs (${JOURNAL_LINES}) =="
journalctl -u "${SERVICE_NAME}" -n "${JOURNAL_LINES}" --no-pager || true

if [[ "${FOLLOW}" == "yes" ]]; then
  echo
  echo "== Following Logs =="
  journalctl -u "${SERVICE_NAME}" -f
fi
