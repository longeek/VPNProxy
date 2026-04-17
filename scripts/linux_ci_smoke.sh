#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

echo "[INFO] Linux smoke: bash syntax check"
bash -n scripts/*.sh

echo "[INFO] Linux smoke: script help checks"
bash scripts/linux_quick_install.sh --help >/dev/null
bash scripts/linux_quick_monitor.sh --help >/dev/null

echo "[INFO] Linux smoke: python test suite"
bash scripts/test.sh

echo "[INFO] Linux smoke: package build"
bash scripts/package.sh ci-smoke

if [[ ! -f "dist/vpnproxy-ci-smoke.tar.gz" ]]; then
  echo "[ERROR] missing package dist/vpnproxy-ci-smoke.tar.gz"
  exit 1
fi

echo "[INFO] Linux smoke checks passed"
