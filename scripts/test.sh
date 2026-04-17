#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PYTHON_BIN="${PYTHON_BIN:-python3}"
WITH_COVERAGE="${WITH_COVERAGE:-auto}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "[ERROR] ${PYTHON_BIN} not found"
  exit 1
fi

cd "${PROJECT_ROOT}"

echo "[INFO] Running unit and integration tests"
"${PYTHON_BIN}" -m unittest discover -s tests -v

if [[ "${WITH_COVERAGE}" == "always" ]] || [[ "${WITH_COVERAGE}" == "auto" && -x "$(command -v coverage || true)" ]]; then
  echo "[INFO] Running coverage report"
  coverage run -m unittest discover -s tests >/dev/null
  coverage report -m
fi

echo "[INFO] Tests completed"
