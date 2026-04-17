#!/usr/bin/env bash
set -euo pipefail

TOKENS_FILE="${1:-/etc/vpn-proxy/tokens.txt}"
COUNT="${2:-5}"
TOKEN_BYTES="${3:-32}"
RESTART_SERVICE="${4:-yes}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/rotate_tokens.sh [tokens_file] [count] [token_bytes] [restart yes|no]"
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found"
  exit 1
fi

if ! [[ "${COUNT}" =~ ^[0-9]+$ ]] || [[ "${COUNT}" -lt 1 ]]; then
  echo "COUNT must be a positive integer"
  exit 1
fi

if ! [[ "${TOKEN_BYTES}" =~ ^[0-9]+$ ]] || [[ "${TOKEN_BYTES}" -lt 16 ]]; then
  echo "TOKEN_BYTES must be an integer >= 16"
  exit 1
fi

mkdir -p "$(dirname "${TOKENS_FILE}")"
tmp_file="$(mktemp)"

{
  echo "# Auto-generated tokens"
  echo "# Generated at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  for _ in $(seq 1 "${COUNT}"); do
    openssl rand -hex "${TOKEN_BYTES}"
  done
} > "${tmp_file}"

chmod 600 "${tmp_file}"

if [[ -f "${TOKENS_FILE}" ]]; then
  cp "${TOKENS_FILE}" "${TOKENS_FILE}.$(date +%Y%m%d%H%M%S).bak"
fi

mv "${tmp_file}" "${TOKENS_FILE}"
chmod 600 "${TOKENS_FILE}"

echo "Rotated tokens file: ${TOKENS_FILE}"
echo "Token count: ${COUNT}"

if [[ "${RESTART_SERVICE}" == "yes" ]]; then
  if systemctl list-unit-files | rg -q "^vpn-proxy\\.service"; then
    systemctl restart vpn-proxy
    echo "Restarted service: vpn-proxy"
  else
    echo "vpn-proxy.service not found; skipped restart."
  fi
fi
