@echo off
title VPN Proxy Client (Go - Auto Select)
cd /d "D:\codes\VPNProxy\vpn-proxy-go"

"bin\vpn-proxy-client.exe" --servers 47.88.49.28:443,47.79.229.128:443 --token 34db557e51e033b80ff4fc9cc42efb305055f57f50cd4226aaaedd3f160bf78a --http-port 8080 --insecure --pool-size 8 --pool-ttl 60

if errorlevel 1 (
  echo.
  echo VPN Proxy Go exited with error. Press any key to close...
  pause >nul
)
