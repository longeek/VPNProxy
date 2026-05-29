# Go VPN Proxy — 部署/优化/测试会话记录

> 日期: 2026-05-29  
> 服务器: 阿里云美国 (AS45102), 47.88.49.28  
> 客户端: Windows, Go vpn-proxy-client  
> 项目: [VPNProxy](https://github.com/your-org/vpnproxy)

---

## 目录

1. [部署流水线](#1-部署流水线)
2. [关键 Bug 修复](#2-关键-bug-修复)
3. [性能基线 vs 优化后](#3-性能基线-vs-优化后)
4. [瓶颈分析](#4-瓶颈分析)
5. [通过试验得到的经验](#5-通过试验得到的经验)
6. [Phase 2 规划](#6-phase-2-规划)
7. [E2E 测试脚本](#7-e2e-测试脚本)

---

## 1. 部署流水线

### 1.1 首次部署 (Python → Go 迁移)

```bash
# 本地交叉编译
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/vpn-proxy-server-linux ./cmd/server/

# 上传 + 部署
scp bin/vpn-proxy-server-linux admin@47.88.49.28:/tmp/
ssh admin@47.88.49.28
  sudo mv /tmp/vpn-proxy-server-linux /opt/vpn-proxy/vpn-proxy-server
  sudo chmod +x /opt/vpn-proxy/vpn-proxy-server
  sudo systemctl restart vpn-proxy
```

### 1.2 systemd 服务配置

```
[Service]
Type=simple
EnvironmentFile=/etc/vpn-proxy/server.env
ExecStart=/opt/vpn-proxy/vpn-proxy-server --listen ${VPN_PROXY_LISTEN} --port ${VPN_PROXY_PORT} ...
User=root
Restart=always
RestartSec=3
```

环境变量文件 `/etc/vpn-proxy/server.env`:
```
VPN_PROXY_LISTEN=0.0.0.0
VPN_PROXY_PORT=443
VPN_PROXY_CERT=/etc/vpn-proxy/server.crt
VPN_PROXY_KEY=/etc/vpn-proxy/server.key
VPN_PROXY_TOKEN=34db557e...
```

### 1.3 本地 Go 客户端启动

```powershell
Start-Process -FilePath "vpn-proxy-client.exe" -ArgumentList @(
  "--server", "47.88.49.28",
  "--server-port", "443",
  "--token", "34db557e...",
  "--proxy-user", "longeek",
  "--proxy-pass", "Mengql123",
  "--http-port", "8080",
  "--insecure"
) -NoNewWindow
```

> ⚠️ 客户端设计为 daemon 模式，主 goroutine 阻塞等待 `<-sigCh` (Ctrl+C)。  
> 在终端直接运行会"卡住"——这是正常行为。用 `Start-Process` 或 `&` 后台运行。

### 1.4 端口变更 8443 → 443

只修改 env 文件一行:
```bash
sudo sed -i 's/VPN_PROXY_PORT=8443/VPN_PROXY_PORT=443/' /etc/vpn-proxy/server.env
sudo systemctl daemon-reload
sudo systemctl restart vpn-proxy
```

> 因为 `User=root`，可以直接绑定 443 端口，无需 `CAP_NET_BIND_SERVICE`。

---

## 2. 关键 Bug 修复

### 2.1 RelayTCPServer 缓冲写入 Bug

**症状**: 服务端日志显示 `up=460 bytes, down=0 bytes` — 客户端发了 TLS ClientHello，目标服务器从未收到。

**根因**: `RelayTCPServer` 使用 `bufio.NewWriterSize(conn, 128*1024)` + `DrainThreshold=128KB`。  
TLS 握手包仅 ~460 字节，远低于 128KB 阈值，永远不被刷出 → 目标服务器收不到请求 → 零字节回传。

**修复**: 上传方向每次 `Write()` 后强制 `Flush()`:

```go
// Upload: tlsConn → target
n, err := tlsConn.Read(bufUp)
if n > 0 {
    bw.Write(bufUp[:n])
    bw.Flush() // ← 关键：小包立即发送
}
```

**效果**: 从 `down=0` → `down=700KB+`，数据开始正常流转。

### 2.2 下载方向 Flush 策略试验（失败的优化）

**尝试**: 下载方向用 graduated flush — 前 8KB 立即刷，之后每 32KB 刷一次。

**结果**: TTFB 从 1.5s → 4.3s，吞吐从 12 KB/s → 10.9 KB/s。

**原因**: 下载方向延迟发送 = 客户端干等。`bufio.Writer` 累积到 32KB 才 flush 意味着客户端在 220ms RTT 链路上多等了几秒才能收到第一个字节。

**回退**: 下载方向恢复 per-write flush。最终确认：**per-write flush 不是瓶颈**。

---

## 3. 性能基线 vs 优化后

### 3.1 数据汇总

| 指标 | 优化前 (8443, 高峰22:30) | 优化后 (443, 深夜23:10) | 提升 |
|------|------------------------|----------------------|------|
| youtube 吞吐 (SOCKS5) | 9.4 KB/s | **282 KB/s** | **30x** |
| youtube 吞吐 (HTTP CONNECT) | 10.5 KB/s | **287 KB/s** | **27x** |
| TTFB (youtube SOCKS5) | 2.24s | **1.2s** | 1.9x |
| baidu.com | 4.72s | **1.75s** | 2.7x |
| 服务端每会话回传 | ~715 KB | **~730 KB** | 不变 |

### 3.2 真实瓶颈评估

```
服务器带宽 (1.97 MB/s to youtube)
  ↓ 充足 ✅
客户端→服务器 (220ms RTT, 国际链路)
  ↓ ⚠️ 主要瓶颈
    ├── 高峰时段 (22:00-23:00): ISP 限速 ~10 KB/s
    ├── 深夜时段 (23:00+):    ~280 KB/s
    └── 端口 8443 vs 443:     443 可能绕过部分 DPI 检测
  ↓
客户端本地 (SOCKS5 → curl)
  ↓ 无瓶颈 ✅
```

**核心发现**: 吞吐瓶颈不在代码，在 **中国 ISP 对国际链路的时段性限速** 和 **端口/协议识别**。

---

## 4. 瓶颈分析

### 4.1 网络层瓶颈

| 因素 | 影响 | 证据 |
|------|------|------|
| 220ms RTT | TCP 拥塞窗口增长慢 | ping 测量 |
| ISP 时段限速 | 高峰 10 KB/s → 深夜 280 KB/s | 30 分钟内 28x 变化 |
| 端口识别 | 8443 被 DPI 标记 | 改 443 后提升 |
| TCP-over-TCP | 双重拥塞控制 | 外层 TCP 丢包 → 内层误判 |

### 4.2 代码层瓶颈

| 组件 | 状态 | 说明 |
|------|------|------|
| per-write flush | ✅ 正常 | 每次 flush 只调 `tls.Conn.Write()`，不进网络等待 |
| bufio.Writer 128KB | ✅ 合理 | 足够大避免频繁 syscall |
| sync.Pool 缓冲复用 | ✅ 高效 | 减少 GC 压力 |
| RelayBidirectional (客户端) | ✅ 正常 | `io.CopyBuffer` 128KB |

### 4.3 错误假设纠正

> ❌ **错误假设**: per-write flush 在 220ms RTT 上每次阻塞 220ms。  
> ✅ **事实**: `bw.Flush()` → `tls.Conn.Write()` → 加密后写到内核 TCP 缓冲区就返回，不等 ACK。所以 per-write flush 的开销是微秒级的。

> ❌ **错误假设**: 增大 flush 阈值可提升吞吐。  
> ✅ **事实**: 增大 flush 阈值只会劣化 TTFB，不影响持续吞吐（因为吞吐受 TCP 拥塞窗口控制，不是 flush 频率）。

---

## 5. 通过试验得到的经验

### 5.1 部署经验

1. **Go 交叉编译** → `GOOS=linux GOARCH=amd64` + `-ldflags="-s -w"` 得到 7MB 静态二进制
2. **systemd env 文件** → 比硬编码参数灵活，改端口只需改一行
3. **root 运行** → 可以直接绑定 443，不需要 `setcap`
4. **`--insecure` 必须加** → 自签名证书客户端默认验证失败
5. **PowerShell `Start-Process`** → 后台启动 daemon 进程的标准方式

### 5.2 测试经验

1. **curl 测速模板**:
   ```powershell
   curl.exe --proxy socks5h://user:pass@127.0.0.1:1080 -s -o NUL `
     -w "HTTP %{http_code} | %{size_download}B | %{speed_download}B/s | TTFB %{time_starttransfer}s" `
     --connect-timeout 10 --max-time 20 https://www.youtube.com
   ```
2. **服务端日志验证** → `journalctl -u vpn-proxy | grep 'session closed'` 查看每会话字节数
3. **netstat 检查** → `netstat -an | Select-String "127.0.0.1.(1080|8080)"` 确认端口监听
4. **`netstat -ano` + PID** → 查哪个进程占端口

### 5.3 调试经验

1. **SOCKS5 验证失败** → `tls: failed to verify certificate` → 加 `--insecure`
2. **zero-byte down** → `RelayTCPServer` buffered writer 未 flush → 加 per-write flush
3. **TTFB 过高** → 下载方向使用大阈值 flush → 改回 per-write flush
4. **端口被占** → 旧 client 没停干净 → `Stop-Process -Force` + `Start-Sleep 2`

---

## 6. Phase 2 规划

### 6.1 可选方案

| 方案 | 预期吞吐 | 成本 | 复杂度 | 前提 |
|------|---------|------|--------|------|
| Let's Encrypt 合法证书 | ~300 KB/s | 免费 | 低 | 需要域名 |
| Cloudflare CDN 代理 | ~500 KB/s | 免费 | 中 | 需要域名 + CF 账号 |
| 阿里云香港 ECS | ~2 MB/s | 付费 | 低 | 迁移服务器 |
| Cloudflare Tunnel | ~300 KB/s | 免费 | 中 | 需要域名 + cloudflared |

### 6.2 推荐路径

```
Phase 2a: 域名 + Let's Encrypt (最简)
  - 购买域名 → 指向 47.88.49.28
  - certbot 获取证书 → 替换 /etc/vpn-proxy/server.crt
  - 客户端去掉 --insecure
  - 预期: 合法证书 → 更少 DPI 标记 → 吞吐可能翻倍

Phase 2b: Cloudflare CDN (可选)
  - DNS 接入 Cloudflare → 开启代理 (橙色云)
  - 隐藏真实 IP + 全球 CDN 边缘节点
  - 注意: 免费版无中国优化节点
```

### 6.3 后续优化方向

- [ ] 获取域名 + Let's Encrypt 证书
- [ ] 配置 Cloudflare DNS/CDN
- [ ] 服务器迁移到香港 (降低 RTT 220ms → 50ms)
- [ ] 探索 KCP/QUIC 替代 TCP 隧道 (避免 TCP-over-TCP)

---

## 7. E2E 测试脚本

**文件**: `scripts/go_deploy_e2e_test.ps1`

### 使用方法

```powershell
# 完整流程: 编译 → 部署 → 测试
$env:VPN_PROXY_TOKEN = 'your-token'
.\scripts\go_deploy_e2e_test.ps1

# 仅测试 (跳过部署)
.\scripts\go_deploy_e2e_test.ps1 -SkipDeploy

# 仅部署 (跳过测试)
.\scripts\go_deploy_e2e_test.ps1 -SkipTests
```

### 测试覆盖

| 测试项 | 命令 | 预期 |
|--------|------|------|
| baidu 可达性 | `curl SOCKS5 baidu.com` | HTTP 200 |
| youtube 吞吐 | `curl SOCKS5 youtube.com` | >200 KB/s |
| HTTP CONNECT | `curl HTTP youtube.com` | >200 KB/s |
| google 可达性 | `curl SOCKS5 google.com` | HTTP 200 |
| 服务端统计 | `journalctl session closed` | 每会话 ~700KB |

### 输出示例

```
=== PREFLIGHT ===
  Remote: admin@47.88.49.28:443
=== S01: Cross-compile ===
[PASS] vpn-proxy-server-linux
=== S02: Upload + deploy ===
[PASS] Server listening on :443
=== S04: Start Go client ===
[PASS] Go client ready (SOCKS5 :1080, HTTP :8080)
=== S05b: youtube SOCKS5 ===
[PASS] HTTP 200 | 703KB | 282 KB/s | TTFB 1.2s
=== S05c: youtube HTTP ===
[PASS] HTTP 200 | 710KB | 287 KB/s | TTFB 1.2s
=== S06: Server stats ===
[PASS] Avg 547 KB/session, total 4.3 MB
```
