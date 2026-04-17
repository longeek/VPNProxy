#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/gen_cert.sh [cert_dir] [common_name] [days] [extra_san]
# extra_san: optional comma-separated entries, e.g. IP:47.88.49.28 or IP:1.2.3.4,DNS:proxy.example.com
# The certificate always includes DNS:<common_name> in subjectAltName.

CERT_DIR="${1:-./certs}"
COMMON_NAME="${2:-vpn-proxy-server}"
DAYS="${3:-825}"
EXTRA_SAN="${4:-}"

mkdir -p "${CERT_DIR}"

SUBJECT_ALT="DNS:${COMMON_NAME}"
if [[ -n "${EXTRA_SAN}" ]]; then
  SUBJECT_ALT="${SUBJECT_ALT},${EXTRA_SAN}"
fi

openssl req -x509 -newkey rsa:4096 \
  -keyout "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.crt" \
  -sha256 -days "${DAYS}" -nodes \
  -subj "/CN=${COMMON_NAME}" \
  -addext "subjectAltName=${SUBJECT_ALT}"

chmod 600 "${CERT_DIR}/server.key"
echo "Generated:"
echo "  ${CERT_DIR}/server.crt"
echo "  ${CERT_DIR}/server.key"
echo "  subjectAltName=${SUBJECT_ALT}"
