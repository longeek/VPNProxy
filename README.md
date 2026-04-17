# Linux VPN Proxy (TLS Tunnel + SOCKS5 / HTTP / TCP / UDP)

这个项目提供一个可在 Linux 运行的“VPN 代理”最小实现：

- 加拿大服务器运行 `server.py`（TLS 加密出口代理）
- 本地设备运行 `client.py`（本地入口，默认 **SOCKS5**，可选 **HTTP CONNECT**、**TCP 行握手**；SOCKS5 支持 **UDP ASSOCIATE**）
- 应用可将代理设为 `socks5://127.0.0.1:1080`，或按需启用 HTTP/TCP 端口

> 仅用于你有权限的网络与主机环境。

## 1. 架构

1. 本地应用任选一种入口连接 `client.py`：**SOCKS5**（TCP `CONNECT` / UDP `UDP ASSOCIATE`）、**HTTP `CONNECT`**、或 **TCP 首行目标**（见下文「多协议说明」）
2. `client.py` 通过 TLS 连接远端服务器 `server.py`
3. 服务器验证 token（支持单 token 或多 token 文件）后，按隧道首包 JSON 中的 **`proto`** 建立 **TCP** 或 **UDP** 中继，并转发流量
4. **TCP 模式**：TLS 隧道内为透明双向字节流；**UDP 模式**：隧道内为带目标地址的定长帧（见下文）

## 2. 环境要求

- Python 3.9+
- Linux 服务器可公网访问（建议开放 `8443/tcp`）
- OpenSSL（用于证书生成）

## 3. 生成证书（在服务器上）

```bash
chmod +x scripts/gen_cert.sh
./scripts/gen_cert.sh ./certs vpn-ca-server 825
```

会生成：

- `certs/server.crt`
- `certs/server.key`

## 4. 启动服务端（加拿大 Linux）

```bash
python3 server.py \
  --listen 0.0.0.0 \
  --port 8443 \
  --cert ./certs/server.crt \
  --key ./certs/server.key \
  --token "YOUR_LONG_RANDOM_TOKEN" \
  --allow-cidrs "你的出口IP/32"
```

### 多 token（多用户）示例

创建 `tokens.txt`（每行一个 token，`#` 开头为注释）：

```text
# user tokens
token_user_a
token_user_b
```

```bash
python3 server.py \
  --listen 0.0.0.0 \
  --port 8443 \
  --cert ./certs/server.crt \
  --key ./certs/server.key \
  --token "fallback_admin_token" \
  --tokens-file ./tokens.txt \
  --allow-cidrs "1.2.3.4/32,10.0.0.0/8"
```

## 5. 启动客户端（本地）

将服务器证书 `server.crt` 复制到本地，例如 `./certs/server.crt`。

```bash
python3 client.py \
  --listen 127.0.0.1 \
  --listen-port 1080 \
  --server <加拿大服务器IP或域名> \
  --server-port 8443 \
  --token "YOUR_LONG_RANDOM_TOKEN" \
  --ca-cert ./certs/server.crt \
  --connect-retries 3 \
  --retry-delay 0.8
```

然后把浏览器或系统代理设置为：

- SOCKS5: `127.0.0.1:1080`

### 5.1 多协议说明（HTTP / TCP / UDP）

#### 隧道首包（客户端 → 服务端，一行 JSON）

客户端在每条 TLS 连接上会先发一行 UTF-8 JSON（以 `\n` 结束），服务端解析后返回 `OK\n` 或错误行。字段约定：

| 字段 | 含义 |
|------|------|
| `auth` | 与 `--token` 一致的共享密钥 |
| `host` / `port` | 目标地址；TCP 模式下为远端 TCP 目标 |
| `proto` | 可选，默认 `tcp`；设为 `udp` 时进入 UDP 中继（见下表） |

**UDP 模式下的 `host` / `port`：**

| `host` | `port` | 含义 |
|--------|--------|------|
| `0.0.0.0` | `0` | **多目的地中继**：每个 UDP 帧内自带目标主机名与端口（SOCKS5 UDP ASSOCIATE 使用此模式） |
| 其他 | `1`–`65535` | **固定目的地**：帧内仍带地址字段，但出站 UDP 一律发往该固定 `host:port` |

UDP 在 TLS 上的帧格式（双向相同，版本字节当前为 `1`）：

`ver(1) + rsv(1) + host_len(2) + host(UTF-8) + port(2, 大端) + payload_len(2, 大端) + payload`

#### 本地 HTTP 代理（`CONNECT`）

适用于走 **HTTP 代理协议** 的应用（浏览器、部分工具链）：

- 参数：`--http-port <端口>`，或环境变量 `VPN_PROXY_HTTP_PORT`（**仅当值为大于 0 的整数时**才会监听；未设置则只开 SOCKS）
- 客户端发送标准请求，首行形如：`CONNECT example.com:443 HTTP/1.1`，后跟常规 HTTP 头并以 `\r\n\r\n` 结束
- 隧道建立成功后，**本地 `client.py`** 向你的应用返回 `HTTP/1.1 200 Connection Established\r\n\r\n`，之后为原始 TCP 流

示例（在保留 SOCKS `1080` 的同时增加 HTTP `8080`）：

```bash
python3 client.py \
  --listen 127.0.0.1 \
  --listen-port 1080 \
  --http-port 8080 \
  --server <服务器> \
  --server-port 8443 \
  --token "YOUR_LONG_RANDOM_TOKEN" \
  --ca-cert ./certs/server.crt
```

系统/浏览器可配置 **HTTP/HTTPS 代理**为 `127.0.0.1:8080`（HTTPS 仍通过 `CONNECT` 走隧道）。

#### 本地 TCP 行协议（极简 TCP 入口）

适用于自定义客户端或脚本：连上后**第一行文本**写目标，然后直接收发原始数据。

- 参数：`--tcp-line-port <端口>`，或环境变量 `VPN_PROXY_TCP_LINE_PORT`（同样 **> 0** 才启用）
- 首行格式（二选一）：`host:port` 或 `host port`（空格分隔，端口为数字）
- 隧道就绪后，**本地 `client.py`** 会先回一行 `OK\n`，再开始双向转发

示例：

```bash
python3 client.py ... --listen-port 1080 --tcp-line-port 1081
# 另开终端：echo -e "example.com:443\n" | nc 127.0.0.1 1081
# 读到 OK 后即可在该连接上发 TLS/明文等 TCP 载荷（需自行协议栈）
```

#### SOCKS5 UDP（`UDP ASSOCIATE`）

- 在 **SOCKS5 端口**（`--listen-port`）上使用命令字 `0x03`（与 `CONNECT` 相同握手前缀，命令为 UDP ASSOCIATE）
- 客户端在 SOCKS 应答里拿到本地 **UDP 中继端口**；应用按 **RFC 1928** 在 UDP 数据前封装 SOCKS UDP 头（`RSV + FRAG + ATYP + 地址 + 端口 + 数据`）
- 隧道侧使用 `host=0.0.0.0`、`port=0`、`proto=udp`，由服务端按帧内目标做 `sendto`
- 返回数据按 **(请求中的目标主机, 目标端口)** 与待发队列做匹配后封装 SOCKS UDP 回复发回应用（并发场景下为 FIFO 匹配；极复杂并发可考虑应用侧序列化或使用 TCP）

> **说明**：服务端 **`server.py` 无需为 HTTP/TCP/UDP 单独开端口**；区别仅在于 TLS 隧道首包 JSON 是否带 `proto` 及 `host`/`port` 取值。多入口都由 **`client.py`** 在本地提供。

## 6. systemd 部署（服务器）

```bash
sudo bash scripts/install_server.sh
```

然后：

1. 把证书放到 `/etc/vpn-proxy/server.crt` 与 `/etc/vpn-proxy/server.key`
2. 编辑 `/etc/vpn-proxy/server.env`，至少设置 `VPN_PROXY_TOKEN`
3. 如需多用户，创建 token 文件并设置 `VPN_PROXY_TOKENS_FILE`
4. 如需白名单，设置 `VPN_PROXY_ALLOW_CIDRS`（例如 `1.2.3.4/32`）
5. 启动服务：

```bash
sudo systemctl restart vpn-proxy
sudo systemctl status vpn-proxy
```

## 7. 一键部署命令（按发行版）

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y python3 openssl ufw
cd /path/to/VPNProxy
chmod +x scripts/gen_cert.sh scripts/install_server.sh scripts/firewall_ufw.sh scripts/rotate_tokens.sh scripts/health_check.sh
./scripts/gen_cert.sh ./certs vpn-ca-server 825
sudo bash scripts/install_server.sh
sudo cp ./certs/server.crt /etc/vpn-proxy/server.crt
sudo cp ./certs/server.key /etc/vpn-proxy/server.key
sudo bash scripts/firewall_ufw.sh 8443 tcp
sudo systemctl restart vpn-proxy
```

### CentOS / RHEL / Rocky / AlmaLinux

```bash
sudo dnf install -y python3 openssl firewalld
cd /path/to/VPNProxy
chmod +x scripts/gen_cert.sh scripts/install_server.sh scripts/firewall_firewalld.sh scripts/rotate_tokens.sh scripts/health_check.sh
./scripts/gen_cert.sh ./certs vpn-ca-server 825
sudo bash scripts/install_server.sh
sudo cp ./certs/server.crt /etc/vpn-proxy/server.crt
sudo cp ./certs/server.key /etc/vpn-proxy/server.key
sudo bash scripts/firewall_firewalld.sh 8443 tcp
sudo systemctl restart vpn-proxy
```

## 8. 日志查看

```bash
sudo journalctl -u vpn-proxy -f
```

每个会话会输出上下行字节统计（`up/down bytes`）。

### 8.1 使用 `sid` 串联日志

`client.py` 与 `server.py` 会为每个会话生成短 ID，日志格式类似：

```text
[sid=ded3ff73] accepted tunnel from ...
[sid=ded3ff73] session closed ... (up=19 bytes, down=24 bytes)
```

排障建议：

- 先在客户端日志里找到失败请求的 `sid`
- 再在服务端日志里搜索同一个 `sid`
- 通过同一 `sid` 可快速定位“客户端握手 -> 服务端鉴权/连接 -> 会话关闭”的完整链路

## 9. Token 轮换（自动）

下面命令会生成新的多用户 token 文件，并备份旧文件：

```bash
sudo bash scripts/rotate_tokens.sh /etc/vpn-proxy/tokens.txt 5 32 yes
```

参数说明：

- 第 1 个参数：token 文件路径（默认 `/etc/vpn-proxy/tokens.txt`）
- 第 2 个参数：token 数量（默认 `5`）
- 第 3 个参数：每个 token 的随机字节数（默认 `32`，最终是 64 位十六进制字符）
- 第 4 个参数：是否自动重启服务（`yes/no`，默认 `yes`）

然后在 `/etc/vpn-proxy/server.env` 中设置：

```bash
VPN_PROXY_TOKENS_FILE=/etc/vpn-proxy/tokens.txt
```

最后重启：

```bash
sudo systemctl restart vpn-proxy
```

## 10. 健康检查（一键）

可直接运行：

```bash
chmod +x scripts/health_check.sh
sudo bash scripts/health_check.sh
```

可选环境变量（不传则使用默认值）：

- `VPN_PROXY_SERVICE_NAME`：systemd 服务名，默认 `vpn-proxy`
- `VPN_PROXY_SERVER_PORT`：监听端口，默认 `8443`
- `VPN_PROXY_SOCKS_ADDR`：本地 SOCKS 地址，默认 `127.0.0.1:1080`
- `VPN_PROXY_TEST_URL`：连通性测试 URL，默认 `https://ifconfig.me`
- `VPN_PROXY_JOURNAL_LINES`：读取日志行数，默认 `120`
- `VPN_PROXY_CURL_TIMEOUT`：curl 超时秒数，默认 `8`

脚本会输出 `PASS/WARN/FAIL` 和最终汇总；只要出现 `FAIL` 就会返回非零退出码。

## 11. 安全建议

- 使用高强度随机 token（至少 32 字符）
- 生产环境建议使用受信任 CA 或你自己的私有 CA
- 配置防火墙仅开放需要端口
- 定期轮换 token 与证书

## 12. SOCKS 错误码对照（客户端）

当本地 SOCKS 请求失败时，`client.py` 会按错误类型返回更精确的 SOCKS `REP`：

- `0x01`：一般性失败（未命中更具体类型）
- `0x02`：连接被规则拒绝（例如隧道鉴权失败 `ERR auth`）
- `0x03`：网络不可达（如 `ENETUNREACH`）
- `0x04`：主机不可达 / DNS 解析失败 / 连接超时
- `0x05`：目标连接被拒绝（如 `ECONNREFUSED`）
- `0x07`：命令不支持（SOCKS5 支持 `CONNECT` 与 `UDP ASSOCIATE`，其他命令会返回此项）
- `0x08`：地址类型不支持（`ATYP` 不支持）

## 13. 自动化：测试、打包、发布

新增了 3 个流水线脚本：

- `scripts/test.sh`：运行自动化测试（可选 coverage）
- `scripts/package.sh`：打包为 `dist/vpnproxy-<version>.tar.gz`
- `scripts/release.sh`：串行执行“测试 -> 打包 -> 生成发布说明”

示例：

```bash
chmod +x scripts/test.sh scripts/package.sh scripts/release.sh

# 仅测试
bash scripts/test.sh

# 打包（不传版本会使用 UTC 时间戳）
bash scripts/package.sh v1.0.0

# 发布准备（会先跑测试，测试失败即终止）
bash scripts/release.sh v1.0.0
```

产物位于 `dist/`：

- `vpnproxy-<version>.tar.gz`
- `vpnproxy-<version>.tar.gz.sha256`（若系统有 sha256 工具）
- `release-<version>.md`

## 14. Linux 快速安装、运行、关闭、监控脚本

新增了 4 个 Linux 运维脚本：

- `scripts/linux_quick_install.sh`
- `scripts/linux_quick_run.sh`
- `scripts/linux_quick_stop.sh`
- `scripts/linux_quick_monitor.sh`

### 14.1 一键安装（含 systemd、证书、启动）

```bash
chmod +x scripts/linux_quick_install.sh
sudo bash scripts/linux_quick_install.sh \
  --token "CHANGE_ME_TO_LONG_RANDOM_TOKEN" \
  --port 8443 \
  --allow-cidrs "你的出口IP/32"
```

可选参数：

- `--tokens-file /etc/vpn-proxy/tokens.txt`：使用多 token 文件
- `--install-dir /opt/vpn-proxy`：自定义安装目录
- `--cert-cn vpn-proxy-server`：自签证书 CN
- `--skip-dep-install`：跳过 apt/dnf/yum 安装依赖
- `--skip-cert-gen`：跳过证书生成（你已有证书时使用）

### 14.2 快速运行（重启服务）

```bash
chmod +x scripts/linux_quick_run.sh
sudo bash scripts/linux_quick_run.sh
```

### 14.3 快速关闭

```bash
chmod +x scripts/linux_quick_stop.sh
sudo bash scripts/linux_quick_stop.sh
```

### 14.4 快速监控（状态 + 端口 + 日志）

```bash
chmod +x scripts/linux_quick_monitor.sh
sudo bash scripts/linux_quick_monitor.sh
```

持续追日志：

```bash
sudo bash scripts/linux_quick_monitor.sh --follow
```

## 15. GitHub Actions 自动化（CI + 打包 + Release）

仓库已新增工作流：`.github/workflows/ci-release.yml`。

### 15.1 自动测试（CI）

触发条件：

- 向 `main/master` 分支 push
- 向 `main/master` 发起 PR
- 手动触发（`workflow_dispatch`）

执行内容：

- Python `3.9` 与 `3.11` 矩阵测试
- 调用 `scripts/test.sh`

### 15.2 自动打包

在 `push` 或手动触发时，会执行 `scripts/package.sh` 并上传产物：

- `vpnproxy-<version>.tar.gz`
- `vpnproxy-<version>.tar.gz.sha256`

版本规则：

- Tag 触发：使用 tag 名（如 `v1.0.0`）
- 手动触发：优先使用输入参数 `version`
- 未提供时：默认 `manual-<run_number>`

### 15.3 自动发布（GitHub Release）

当你 push `v*` 标签（例如 `v1.0.0`）时：

1. 自动跑测试
2. 自动打包
3. 自动创建 GitHub Release 并上传产物

本地发布示例：

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 16. Windows 本地模拟 Linux 测试（WSL）

如果你的开发机是 Windows，推荐用 WSL2 作为 Linux 运行环境做脚本冒烟和集成测试。

新增脚本：

- `scripts/linux_ci_smoke.sh`：Linux 侧测试入口（脚本语法 + help + 自动化测试 + 打包）
- `scripts/windows_wsl_test.ps1`：Windows 侧一键调用 WSL 执行上述测试

### 16.1 一次性准备（Windows）

```powershell
wsl --install -d Ubuntu
```

安装完成并重启后，在项目根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_wsl_test.ps1 -Distro Ubuntu
```

如需在 WSL 内自动安装依赖（`python3` 等）：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_wsl_test.ps1 -Distro Ubuntu -InstallDeps
```

### 16.2 这套测试覆盖什么

- Bash 脚本语法检查：`bash -n scripts/*.sh`
- 冒烟检查：`linux_quick_install.sh --help`、`linux_quick_monitor.sh --help`
- 集成测试：`scripts/test.sh`（含现有 `test_integration.py`）
- 打包验证：`scripts/package.sh ci-smoke` 并确认产物存在
