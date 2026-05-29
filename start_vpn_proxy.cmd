@echo off
title VPNProxy Client
cd /d "D:\codes\VPNProxy"
"C:\Users\mengqinglong\AppData\Local\Programs\Python\Python311\python.EXE" -u "D:\codes\VPNProxy\client.py" --listen 127.0.0.1 --listen-port 1080 --server 127.0.0.1 --server-port 8443 --token integration_test_token_only --http-port 8080 --pool-size 2 --pool-ttl 8
if errorlevel 1 (
  echo.
  echo VPNProxy exited with error. Press any key to close...
  pause >nul
)
