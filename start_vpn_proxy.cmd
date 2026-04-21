@echo off
title VPNProxy Client
cd /d "D:\codes\VPNProxy"
"C:\Users\mengqinglong\AppData\Local\Programs\Python\Python311\python.exe" -u "D:\codes\VPNProxy\client.py" --listen 127.0.0.1 --listen-port 1080 --server 47.88.49.28 --server-port 8443 --token 34db557e51e033b80ff4fc9cc42efb305055f57f50cd4226aaaedd3f160bf78a --insecure --http-port 8080 --pool-size 2 --pool-ttl 8 --proxy-user longeek --proxy-pass Mengql123
if errorlevel 1 (
  echo.
  echo VPNProxy exited with error. Press any key to close...
  pause >nul
)
