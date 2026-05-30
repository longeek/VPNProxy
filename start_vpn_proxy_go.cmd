@echo off
title VPN Proxy Client (Go - Reuse Mode)
cd /d "D:\codes\VPNProxy\vpn-proxy-go"

echo ========================================
echo   VPN Proxy Client (Go) - Reuse Mode
echo   SOCKS5: 127.0.0.1:1080
echo   HTTP:   127.0.0.1:8080
echo   Pool:   32 connections, 120s TTL
echo   Servers: 47.79.229.128:443 (JP)
echo           47.89.212.234:443 (HK)
echo ========================================
echo.

"bin\vpn-proxy-client.exe" --listen 127.0.0.1 --listen-port 1080 --servers 47.79.229.128:443,47.89.212.234:443 --token 34db557e51e033b80ff4fc9cc42efb305055f57f50cd4226aaaedd3f160bf78a --http-port 8080 --insecure --reuse --pool-size 32 --pool-ttl 120

if errorlevel 1 (
  echo.
  echo VPN Proxy exited with error. Press any key to close...
  pause >nul
)
