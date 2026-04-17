# VPNProxy 安装部署与人工测试手册

本手册用于人工安装、部署、连通性验证与回归测试。

---

## 1. 测试目标

- 在加拿大 Linux 服务器成功部署 `VPNProxy` 服务端
- 本地客户端通过 SOCKS5 使用代理
- 验证正常转发、鉴权、白名单、防火墙、日志、token 轮换等关键能力

---

## 2. 组件说明

- 服务端：`server.py`（部署在加拿大 Linux）
- 客户端：`client.py`（运行在本地机器）
- 证书脚本：`scripts/gen_cert.sh`
- 服务安装脚本：`scripts/install_server.sh`
- 防火墙脚本：
  - `scripts/firewall_ufw.sh`
  - `scripts/firewall_firewalld.sh`
- token 轮换脚本：`scripts/rotate_tokens.sh`

---

## 3. 前置准备

### 3.1 服务器要求（加拿大）

- Linux（Ubuntu/Debian 或 CentOS/RHEL/Rocky/Alma）
- 可公网访问
- 计划开放端口：`8443/tcp`
- 已安装 `python3`、`openssl`

### 3.2 本地要求

- Python 3.9+
- 可访问加拿大服务器 IP/域名
- 可配置应用代理为 SOCKS5

---

## 4. 服务端安装部署

以下步骤在**加拿大 Linux**执行。

### 4.1 上传项目

将项目目录上传到服务器，例如 `/opt/VPNProxy`。

### 4.2 生成证书

```bash
cd /opt/VPNProxy
chmod +x scripts/gen_cert.sh
./scripts/gen_cert.sh ./certs vpn-ca-server 825
```

### 4.3 安装 systemd 服务

```bash
cd /opt/VPNProxy
chmod +x scripts/install_server.sh
sudo bash scripts/install_server.sh
sudo cp ./certs/server.crt /etc/vpn-proxy/server.crt
sudo cp ./certs/server.key /etc/vpn-proxy/server.key
```

### 4.4 配置服务参数

编辑 ` /etc/vpn-proxy/server.env `，至少设置：

```bash
VPN_PROXY_TOKEN=CHANGE_TO_LONG_RANDOM_TOKEN
```

可选增强项：

```bash
VPN_PROXY_TOKENS_FILE=/etc/vpn-proxy/tokens.txt
VPN_PROXY_ALLOW_CIDRS=你的出口IP/32
VPN_PROXY_PORT=8443
```

### 4.5 启动服务

```bash
sudo systemctl daemon-reload
sudo systemctl restart vpn-proxy
sudo systemctl status vpn-proxy
```

---

## 5. 防火墙配置

### 5.1 Ubuntu / Debian（ufw）

```bash
cd /opt/VPNProxy
chmod +x scripts/firewall_ufw.sh
sudo bash scripts/firewall_ufw.sh 8443 tcp
```

### 5.2 CentOS / RHEL / Rocky / Alma（firewalld）

```bash
cd /opt/VPNProxy
chmod +x scripts/firewall_firewalld.sh
sudo bash scripts/firewall_firewalld.sh 8443 tcp
```

---

## 6. 客户端启动与使用

在本地机器执行：

1. 从服务器下载 `server.crt` 到本地，例如 `./certs/server.crt`
2. 启动客户端：

```bash
python3 client.py \
  --listen 127.0.0.1 \
  --listen-port 1080 \
  --server <加拿大服务器IP或域名> \
  --server-port 8443 \
  --token "CHANGE_TO_LONG_RANDOM_TOKEN" \
  --ca-cert ./certs/server.crt \
  --connect-retries 3 \
  --retry-delay 0.8
```

3. 将浏览器或系统代理设置为：
   - SOCKS5：`127.0.0.1:1080`

---

## 7. 人工测试执行清单（可勾选）

使用方式：

1. 按顺序执行每条用例，在 `结果` 列打勾。
2. 在 `证据` 列记录日志位置、命令输出或截图文件名。
3. 若失败，在 `备注` 列写明现象与初步原因。

> 建议优先级：先 `T01~T04` 建立可用基线，再执行 `T05/T06/T10` 安全关键项。

| ID | 用例 | 操作 | 预期 | 结果 | 证据 | 备注 |
|---|---|---|---|---|---|---|
| T01 | 服务存活检查 | `sudo systemctl status vpn-proxy` | 状态为 `active (running)` | [ ] 通过 [ ] 失败 |  |  |
| T02 | 端口监听检查 | `ss -lntp | rg 8443` | 监听 `0.0.0.0:8443` 或指定地址 | [ ] 通过 [ ] 失败 |  |  |
| T03 | 代理链路正向验证（浏览器） | 浏览器配置 SOCKS5 后访问 `https://ifconfig.me` | 出口 IP 显示为加拿大服务器 IP | [ ] 通过 [ ] 失败 |  |  |
| T04 | 代理链路正向验证（命令行） | `curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me` | 返回公网出口 IP，且为服务器 IP | [ ] 通过 [ ] 失败 |  |  |
| T05 | 错误 token 验证 | 客户端使用错误 `--token` 后发起请求 | 请求失败；服务端日志出现 `auth failed` | [ ] 通过 [ ] 失败 |  |  |
| T06 | CIDR 白名单验证 | `VPN_PROXY_ALLOW_CIDRS=正确出口IP/32`，允许/非允许 IP 分别测试 | 允许 IP 可连通；非允许 IP 被拒绝并出现 `peer not in allow-cidrs` | [ ] 通过 [ ] 失败 |  |  |
| T07 | 客户端重试机制验证 | 暂停服务端后发起请求，再恢复服务端 | 出现 `tunnel connect failed` 重试日志；恢复后可连通 | [ ] 通过 [ ] 失败 |  |  |
| T08 | 流量日志验证 | `sudo journalctl -u vpn-proxy -f` 观察成功请求日志 | 出现 `session closed ... (up=xxx bytes, down=xxx bytes)` | [ ] 通过 [ ] 失败 |  |  |
| T09 | 多 token 验证 | 配置 `VPN_PROXY_TOKENS_FILE`，使用文件内外 token 分别连接 | 文件内 token 通过；文件外 token 被拒绝 | [ ] 通过 [ ] 失败 |  |  |
| T10 | token 轮换验证 | `sudo bash scripts/rotate_tokens.sh /etc/vpn-proxy/tokens.txt 5 32 yes`，新旧 token 分别测试 | 旧 token 失效（若不在新文件中）；新 token 生效；服务重启成功 | [ ] 通过 [ ] 失败 |  |  |

### 7.1 发布门禁（Go/No-Go）

- 必须通过：`T01`、`T02`、`T03`、`T04`、`T05`、`T06`、`T10`
- 建议通过：`T07`、`T08`、`T09`
- 任一“必须通过”失败：结论为 `No-Go`，需修复后回归
- 允许发布（`Go`）条件：所有“必须通过”项为通过

---

## 8. 常见问题排查

- 日志链路追踪（推荐）：
  - 在客户端或服务端日志中定位 `sid`（格式如 `[sid=abc123ef]`）
  - 用同一个 `sid` 关联两端日志，快速确认失败发生在“本地 SOCKS 握手 / 隧道建立 / 服务端出口连接”哪个阶段
- 服务未启动：
  - `sudo journalctl -u vpn-proxy -n 200 --no-pager`
  - 检查证书路径与权限（`/etc/vpn-proxy/server.key` 建议 `600`）
- 客户端连不上：
  - 检查服务器安全组/防火墙是否开放 `8443/tcp`
  - 检查 `--server`、`--token`、`--ca-cert` 是否一致
- 证书验证失败：
  - 确认客户端使用的 `server.crt` 与服务端当前证书匹配

### 8.1 SOCKS 错误码排障对照

当应用通过本地 SOCKS5 访问失败时，可结合客户端日志中的 `reply=0x..` 快速判断原因：

| REP | 含义 | 常见触发场景 |
|---|---|---|
| `0x01` | 一般性失败 | 未命中特定错误类型 |
| `0x02` | 连接被规则拒绝 | 服务端返回 `ERR auth`（token 不匹配） |
| `0x03` | 网络不可达 | 路由/网络不可达（`ENETUNREACH`） |
| `0x04` | 主机不可达 | DNS 失败、主机不可达、连接超时 |
| `0x05` | 连接被拒绝 | 目标端口未监听（`ECONNREFUSED`） |
| `0x07` | 命令不支持 | 客户端发起的不是 `CONNECT` |
| `0x08` | 地址类型不支持 | `ATYP` 非 IPv4/域名/IPv6 |

---

## 9. 测试结论与签字

### 9.1 执行信息

- 测试日期：
- 测试环境（服务器 OS / 客户端 OS）：
- 服务端版本（提交号或打包版本）：
- 执行人：

### 9.2 统计结果

- 通过数：
- 失败数：
- 阻塞数（如有）：
- 必须通过项是否全部通过（是/否）：

### 9.3 失败项与处置

- 失败用例 ID：
- 现象描述：
- 关联日志/截图：
- 处置建议：

### 9.4 最终结论

- 发布结论：`Go` / `No-Go`
- 结论说明：
- 审核人（可选）：

---

## 10. 最小排障命令清单（建议按顺序执行）

以下命令覆盖 80% 常见故障定位场景。建议先从服务端确认“进程与端口”，再看日志与端到端链路。

1) 服务端状态（systemd）

```bash
sudo systemctl status vpn-proxy --no-pager
```

2) 服务端端口监听（8443）

```bash
ss -lntp | rg 8443
```

3) 服务端最近日志（快速看报错）

```bash
sudo journalctl -u vpn-proxy -n 200 --no-pager
```

4) 服务端实时日志（观察一次真实请求）

```bash
sudo journalctl -u vpn-proxy -f
```

5) 本地 SOCKS 端到端连通（命令行）

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

6) 一键健康检查（推荐）

```bash
chmod +x scripts/health_check.sh
sudo bash scripts/health_check.sh
```

### 10.1 常用定位技巧

- 若 `curl` 失败，先看客户端日志中的 `reply=0x..`，按 8.1 对照表定位失败类型。
- 在日志中抓到 `sid` 后，分别在 client/server 日志搜索相同 `sid`，可快速定位失败阶段。
- 若服务端无任何请求日志，优先排查安全组/防火墙/路由是否放通 `8443/tcp`。
- 如需自定义检查目标，可临时设置环境变量：`VPN_PROXY_SERVICE_NAME`、`VPN_PROXY_SERVER_PORT`、`VPN_PROXY_SOCKS_ADDR`、`VPN_PROXY_TEST_URL`。
