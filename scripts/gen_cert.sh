#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/gen_cert.sh [cert_dir] [common_name] [days] [extra_san] [algo]
# algo: ecdsa (default) or rsa
# extra_san: optional comma-separated entries, e.g. IP:47.88.49.28 or IP:1.2.3.4,DNS:proxy.example.com
# The certificate always includes DNS:<common_name> in subjectAltName.

CERT_DIR="${1:-./certs}"
COMMON_NAME="${2:-vpn-proxy-server}"
DAYS="${3:-825}"
EXTRA_SAN="${4:-}"
ALGO="${5:-ecdsa}"

mkdir -p "${CERT_DIR}"

SUBJECT_ALT="DNS:${COMMON_NAME}"
if [[ -n "${EXTRA_SAN}" ]]; then
  SUBJECT_ALT="${SUBJECT_ALT},${EXTRA_SAN}"
fi

if [[ "${ALGO}" == "rsa" ]]; then
  openssl req -x509 -newkey rsa:4096 \
    -keyout "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.crt" \
    -sha256 -days "${DAYS}" -nodes \
    -subj "/CN=${COMMON_NAME}" \
    -addext "subjectAltName=${SUBJECT_ALT}"
else
  openssl ecparam -genkey -name prime256v1 -noout -out "${CERT_DIR}/server.key"
  openssl req -x509 -new -key "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.crt" \
    -sha256 -days "${DAYS}" -nodes \
    -subj "/CN=${COMMON_NAME}" \
    -addext "subjectAltName=${SUBJECT_ALT}"
fi

chmod 600 "${CERT_DIR}/server.key"
echo "Generated (${ALGO}):"
echo "  ${CERT_DIR}/server.crt"
echo "  ${CERT_DIR}/server.key"
echo "  subjectAltName=${SUBJECT_ALT}"
