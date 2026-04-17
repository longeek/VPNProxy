#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  VERSION="$(date -u +%Y%m%d%H%M%S)"
fi

ARTIFACT_NAME="vpnproxy-${VERSION}.tar.gz"
ARTIFACT_PATH="${DIST_DIR}/${ARTIFACT_NAME}"

mkdir -p "${DIST_DIR}"

echo "[INFO] Building artifact ${ARTIFACT_NAME}"
tar \
  --exclude-vcs \
  --exclude="./dist" \
  --exclude="./.venv" \
  --exclude="./.idea" \
  --exclude="./.cursor" \
  --exclude="__pycache__" \
  --exclude="*.pyc" \
  -czf "${ARTIFACT_PATH}" \
  -C "${PROJECT_ROOT}" \
  .

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${DIST_DIR}" && sha256sum "${ARTIFACT_NAME}" > "${ARTIFACT_NAME}.sha256")
elif command -v shasum >/dev/null 2>&1; then
  (cd "${DIST_DIR}" && shasum -a 256 "${ARTIFACT_NAME}" > "${ARTIFACT_NAME}.sha256")
else
  echo "[WARN] No SHA256 tool found, skipped checksum generation"
fi

echo "[INFO] Package ready: ${ARTIFACT_PATH}"
