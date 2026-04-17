#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL_DIR="/opt/vpn-proxy"
ENV_FILE="/etc/vpn-proxy/server.env"
PORT="8443"
TOKEN=""
ALLOW_CIDRS=""
TOKENS_FILE=""
CERT_CN="vpn-proxy-server"
SKIP_DEP_INSTALL="no"
SKIP_CERT_GEN="no"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/linux_quick_install.sh --token <token> [options]

Options:
  --token <token>               Shared token for server auth
  --tokens-file <path>          Optional tokens file path (one token per line)
  --allow-cidrs <cidr_list>     Optional CIDR allowlist, e.g. 1.2.3.4/32,10.0.0.0/8
  --port <port>                 Server listen port (default: 8443)
  --install-dir <path>          Project install path (default: /opt/vpn-proxy)
  --cert-cn <common_name>       Self-signed cert CN (default: vpn-proxy-server)
  --skip-dep-install            Skip apt/dnf/yum package installation
  --skip-cert-gen               Skip certificate generation
  -h, --help                    Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token)
      TOKEN="${2:-}"
      shift 2
      ;;
    --tokens-file)
      TOKENS_FILE="${2:-}"
      shift 2
      ;;
    --allow-cidrs)
      ALLOW_CIDRS="${2:-}"
      shift 2
      ;;
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --cert-cn)
      CERT_CN="${2:-}"
      shift 2
      ;;
    --skip-dep-install)
      SKIP_DEP_INSTALL="yes"
      shift
      ;;
    --skip-cert-gen)
      SKIP_CERT_GEN="yes"
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

if [[ -z "${TOKEN}" && -z "${TOKENS_FILE}" ]]; then
  echo "[ERROR] You must set --token or --tokens-file"
  exit 1
fi

if ! [[ "${PORT}" =~ ^[0-9]+$ ]] || [[ "${PORT}" -lt 1 || "${PORT}" -gt 65535 ]]; then
  echo "[ERROR] --port must be 1..65535"
  exit 1
fi

install_deps() {
  if [[ "${SKIP_DEP_INSTALL}" == "yes" ]]; then
    echo "[INFO] Skipping dependency install"
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 openssl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 openssl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 openssl
  else
    echo "[WARN] Unsupported package manager, install python3 and openssl manually"
  fi
}

copy_project() {
  mkdir -p "${INSTALL_DIR}"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
      --exclude '.git' \
      --exclude '.venv' \
      --exclude '.cursor' \
      --exclude 'dist' \
      --exclude '__pycache__' \
      "${PROJECT_ROOT}/" "${INSTALL_DIR}/"
  else
    cp -a "${PROJECT_ROOT}/." "${INSTALL_DIR}/"
  fi
}

configure_env() {
  export ENV_FILE TOKEN PORT ALLOW_CIDRS TOKENS_FILE
  python3 - <<'PY'
import os
from pathlib import Path

env_file = Path(os.environ["ENV_FILE"])
token = os.environ["TOKEN"]
port = os.environ["PORT"]
allow_cidrs = os.environ["ALLOW_CIDRS"]
tokens_file = os.environ["TOKENS_FILE"]

lines = []
if env_file.exists():
    lines = env_file.read_text(encoding="utf-8").splitlines()

kv = {}
for line in lines:
    if not line or line.lstrip().startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    kv[key] = value

kv["VPN_PROXY_PORT"] = port
if token:
    kv["VPN_PROXY_TOKEN"] = token
kv["VPN_PROXY_TOKENS_FILE"] = tokens_file
kv["VPN_PROXY_ALLOW_CIDRS"] = allow_cidrs

ordered_keys = [
    "VPN_PROXY_LISTEN",
    "VPN_PROXY_PORT",
    "VPN_PROXY_CERT",
    "VPN_PROXY_KEY",
    "VPN_PROXY_TOKEN",
    "VPN_PROXY_TOKENS_FILE",
    "VPN_PROXY_ALLOW_CIDRS",
    "VPN_PROXY_CONNECT_TIMEOUT",
    "VPN_PROXY_LOG_LEVEL",
]

defaults = {
    "VPN_PROXY_LISTEN": "0.0.0.0",
    "VPN_PROXY_CERT": "/etc/vpn-proxy/server.crt",
    "VPN_PROXY_KEY": "/etc/vpn-proxy/server.key",
    "VPN_PROXY_CONNECT_TIMEOUT": "8",
    "VPN_PROXY_LOG_LEVEL": "INFO",
    "VPN_PROXY_TOKEN": "",
    "VPN_PROXY_TOKENS_FILE": "",
    "VPN_PROXY_ALLOW_CIDRS": "",
}

for key, value in defaults.items():
    kv.setdefault(key, value)

output = []
for key in ordered_keys:
    output.append(f"{key}={kv.get(key, '')}")

env_file.write_text("\n".join(output) + "\n", encoding="utf-8")
PY
  chmod 600 "${ENV_FILE}"
}

echo "[INFO] Installing dependencies"
install_deps

echo "[INFO] Copying project to ${INSTALL_DIR}"
copy_project

# install_server.sh copies server.py from current directory; after copy_project,
# INSTALL_DIR is a full tree and cwd there makes cp server.py -> same file.
cd "${PROJECT_ROOT}"
echo "[INFO] Installing systemd service"
bash scripts/install_server.sh

cd "${INSTALL_DIR}"
if [[ "${SKIP_CERT_GEN}" != "yes" ]]; then
  if [[ ! -f "/etc/vpn-proxy/server.crt" || ! -f "/etc/vpn-proxy/server.key" ]]; then
    echo "[INFO] Generating self-signed certificate"
    bash scripts/gen_cert.sh /etc/vpn-proxy "${CERT_CN}" 825
  else
    echo "[INFO] Existing certificate found, skip generation"
  fi
fi

echo "[INFO] Updating ${ENV_FILE}"
configure_env

echo "[INFO] Starting service"
systemctl daemon-reload
systemctl enable vpn-proxy
systemctl restart vpn-proxy
systemctl --no-pager --full status vpn-proxy || true

echo "[INFO] Install completed"
echo "[INFO] Monitor logs with: sudo bash ${INSTALL_DIR}/scripts/linux_quick_monitor.sh --follow"
