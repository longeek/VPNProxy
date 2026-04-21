#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/install_server.sh"
  exit 1
fi

APP_DIR="/opt/vpn-proxy"
ENV_FILE="/etc/vpn-proxy/server.env"
SERVICE_FILE="/etc/systemd/system/vpn-proxy.service"

mkdir -p "${APP_DIR}"
mkdir -p /etc/vpn-proxy

cp server.py "${APP_DIR}/server.py"

if [[ ! -f "${ENV_FILE}" ]]; then
  cat > "${ENV_FILE}" <<'EOF'
VPN_PROXY_LISTEN=0.0.0.0
VPN_PROXY_PORT=8443
VPN_PROXY_CERT=/etc/vpn-proxy/server.crt
VPN_PROXY_KEY=/etc/vpn-proxy/server.key
VPN_PROXY_TOKEN=CHANGE_ME_TO_A_LONG_RANDOM_TOKEN
VPN_PROXY_TOKENS_FILE=
VPN_PROXY_ALLOW_CIDRS=
VPN_PROXY_CONNECT_TIMEOUT=8
VPN_PROXY_BOOTSTRAP_TIMEOUT=30
VPN_PROXY_BACKLOG=512
VPN_PROXY_LOG_LEVEL=INFO
EOF
  chmod 600 "${ENV_FILE}"
fi

cat > "${SERVICE_FILE}" <<'EOF'
[Unit]
Description=VPN Proxy TLS Tunnel Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/vpn-proxy/server.env
ExecStart=/usr/bin/python3 /opt/vpn-proxy/server.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vpn-proxy

echo "Installed."
echo "Next steps:"
echo "1) Place cert and key into /etc/vpn-proxy/"
echo "   Recommended: ./scripts/gen_cert.sh /etc/vpn-proxy ecdsa (ECDSA P-256, fast TLS handshake)"
echo "   Legacy:      ./scripts/gen_cert.sh /etc/vpn-proxy vpn-proxy-server 825 '' rsa (RSA-4096)"
echo "2) Edit ${ENV_FILE} and set VPN_PROXY_TOKEN"
echo "3) Start service: systemctl restart vpn-proxy"
echo "4) Check status:  systemctl status vpn-proxy"
echo ""
echo "Multi-worker deployment (optional, for high concurrency):"
echo "  See scripts/nginx_vpn_proxy.conf for nginx load balancer config"
