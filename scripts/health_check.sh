#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${VPN_PROXY_SERVICE_NAME:-vpn-proxy}"
SERVER_PORT="${VPN_PROXY_SERVER_PORT:-8443}"
SOCKS_ADDR="${VPN_PROXY_SOCKS_ADDR:-127.0.0.1:1080}"
TEST_URL="${VPN_PROXY_TEST_URL:-https://ifconfig.me}"
JOURNAL_LINES="${VPN_PROXY_JOURNAL_LINES:-120}"
CURL_TIMEOUT="${VPN_PROXY_CURL_TIMEOUT:-8}"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

print_header() {
  echo "== VPNProxy Health Check =="
  echo "service=${SERVICE_NAME} port=${SERVER_PORT} socks=${SOCKS_ADDR} url=${TEST_URL}"
  echo
}

pass() {
  local msg="$1"
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] ${msg}"
}

fail() {
  local msg="$1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "[FAIL] ${msg}"
}

warn() {
  local msg="$1"
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] ${msg}"
}

check_service_status() {
  echo "1) systemd status"
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    pass "service is active"
  else
    fail "service is not active (${SERVICE_NAME})"
    systemctl status "${SERVICE_NAME}" --no-pager || true
  fi
  echo
}

check_listen_port() {
  echo "2) listen port"
  local out
  out="$(ss -lntp || true)"
  if [[ -z "${out}" ]]; then
    fail "ss returned no output"
    echo
    return
  fi

  if printf '%s\n' "${out}" | rg -q "[:.]${SERVER_PORT}\\b"; then
    pass "port ${SERVER_PORT} is listening"
    printf '%s\n' "${out}" | rg "[:.]${SERVER_PORT}\\b" || true
  else
    fail "port ${SERVER_PORT} not found in listen sockets"
  fi
  echo
}

check_recent_logs() {
  echo "3) recent logs"
  local logs
  logs="$(journalctl -u "${SERVICE_NAME}" -n "${JOURNAL_LINES}" --no-pager || true)"
  if [[ -z "${logs}" ]]; then
    fail "no journal output for service"
    echo
    return
  fi

  pass "journal logs fetched (${JOURNAL_LINES} lines)"
  printf '%s\n' "${logs}" | rg -n "\\[sid=" || warn "no [sid=...] found in recent logs"
  echo
}

check_socks_chain() {
  echo "4) socks e2e curl"
  if ! command -v curl >/dev/null 2>&1; then
    fail "curl is not installed"
    echo
    return
  fi

  local curl_out
  if curl_out="$(curl --silent --show-error --fail --max-time "${CURL_TIMEOUT}" --socks5-hostname "${SOCKS_ADDR}" "${TEST_URL}" 2>&1)"; then
    pass "curl via SOCKS succeeded"
    echo "response: ${curl_out}"
  else
    fail "curl via SOCKS failed"
    echo "${curl_out}"
  fi
  echo
}

print_summary() {
  echo "== Summary =="
  echo "pass=${PASS_COUNT} warn=${WARN_COUNT} fail=${FAIL_COUNT}"
  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    echo "result=FAIL"
    exit 1
  fi
  if [[ "${WARN_COUNT}" -gt 0 ]]; then
    echo "result=PASS_WITH_WARNINGS"
    exit 0
  fi
  echo "result=PASS"
}

main() {
  if ! command -v rg >/dev/null 2>&1; then
    echo "[FAIL] rg is required but not installed"
    exit 1
  fi
  if ! command -v ss >/dev/null 2>&1; then
    echo "[FAIL] ss is required but not installed"
    exit 1
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "[FAIL] systemctl is required but not installed"
    exit 1
  fi
  if ! command -v journalctl >/dev/null 2>&1; then
    echo "[FAIL] journalctl is required but not installed"
    exit 1
  fi

  print_header
  check_service_status
  check_listen_port
  check_recent_logs
  check_socks_chain
  print_summary
}

main "$@"
