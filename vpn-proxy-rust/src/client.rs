use vpn_proxy::client_logic::{
    check_http_basic_auth, pack_udp_frame, parse_http_connect_target, parse_tcp_line_target,
    socks_udp_build_reply, socks_udp_parse_request,
    UDP_FRAME_VERSION,
};
use vpn_proxy::server_logic::{
    next_session_id,
    PIPE_BUF_SIZE, RECV_BUF_SIZE, DRAIN_THRESHOLD,
};

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, info, warn, Level};
use tracing_subscriber::EnvFilter;

const SOCKS_VERSION: u8 = 5;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn set_socket_opts(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_nodelay(true);
    let _ = sock.set_recv_buffer_size(RECV_BUF_SIZE);
    let _ = sock.set_send_buffer_size(RECV_BUF_SIZE);
}

type TlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

#[derive(Parser)]
#[command(name = "vpn-proxy-client")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    listen: String,
    #[arg(long, default_value_t = 1080)]
    listen_port: u16,
    #[arg(long)]
    http_port: Option<u16>,
    #[arg(long)]
    tcp_line_port: Option<u16>,
    #[arg(long)]
    server: Option<String>,
    #[arg(long, default_value_t = 8443)]
    server_port: u16,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    ca_cert: Option<String>,
    #[arg(long)]
    sni: Option<String>,
    #[arg(long, default_value_t = 2)]
    connect_retries: u32,
    #[arg(long, default_value_t = 0.8)]
    retry_delay: f64,
    #[arg(long, default_value = "false")]
    insecure: bool,
    #[arg(long, default_value_t = 0)]
    pool_size: usize,
    #[arg(long, default_value_t = 8.0)]
    pool_ttl: f64,
    #[arg(long)]
    proxy_user: Option<String>,
    #[arg(long)]
    proxy_pass: Option<String>,
    #[arg(long, default_value = "INFO")]
    log_level: String,
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(&self, _end_entity: &rustls::pki_types::CertificateDer<'_>, _intermediates: &[rustls::pki_types::CertificateDer<'_>], _server_name: &rustls::pki_types::ServerName<'_>, _ocsp_response: &[u8], _now: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _sig: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _sig: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::RSA_PKCS1_SHA256, rustls::SignatureScheme::RSA_PSS_SHA256]
    }
}

fn build_tls_config(cli: &Cli) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();

    for cert in rustls_native_certs::load_native_certs().expect("could not load native certs") {
        root_store.add(cert).ok();
    }

    if let Some(ref ca_cert) = cli.ca_cert {
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(ca_cert).expect("cannot open CA cert")
        )).collect::<Result<Vec<_>, _>>().expect("cannot parse CA cert");
        for cert in certs { root_store.add(cert).expect("cannot add CA cert"); }
    }

    let builder = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if cli.insecure {
        let mut config = builder;
        config.dangerous().set_certificate_verifier(Arc::new(NoVerifier));
        Arc::new(config)
    } else {
        Arc::new(builder)
    }
}

async fn open_tunnel(
    server: &str, server_port: u16, token: &str, tls_config: Arc<rustls::ClientConfig>,
    target_host: &str, target_port: u16, proto: &str, sni: Option<&str>,
    retries: u32, retry_delay: f64,
) -> std::io::Result<TlsStream> {
    use rustls::pki_types::ServerName;
    let server_name: ServerName<'_> = sni.unwrap_or(server)
        .try_into().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;

    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..=retries {
        if attempt > 0 {
            let delay = Duration::from_secs_f64(retry_delay * 2f64.powi(attempt as i32 - 1));
            tokio::time::sleep(delay).await;
        }

        let tcp = match TcpStream::connect((server, server_port)).await {
            Ok(s) => s,
            Err(e) => { last_err = Some(e); continue; }
        };
        set_socket_opts(&tcp);

        let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
        let mut tls = match connector.connect(server_name.to_owned(), tcp).await {
            Ok(s) => s,
            Err(e) => { last_err = Some(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e)); continue; }
        };

        let mut payload = serde_json::json!({ "auth": token, "host": target_host, "port": target_port });
        if proto != "tcp" { payload["proto"] = serde_json::Value::String(proto.to_string()); }
        let bootstrap = serde_json::to_string(&payload).unwrap() + "\n";

        if let Err(e) = tls.write_all(bootstrap.as_bytes()).await { last_err = Some(e); continue; }
        if let Err(e) = tls.flush().await { last_err = Some(e); continue; }

        let mut status_buf = vec![0u8; 64];
        match tokio::time::timeout(Duration::from_secs(10), tls.read(&mut status_buf)).await {
            Ok(Ok(n)) => {
                let status = String::from_utf8_lossy(&status_buf[..n]);
                if status.starts_with("OK") { return Ok(tls); }
                last_err = Some(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, status.trim().to_string()));
                continue;
            }
            Ok(Err(e)) => { last_err = Some(e); continue; }
            Err(_) => { last_err = Some(std::io::Error::new(std::io::ErrorKind::TimedOut, "bootstrap timeout")); continue; }
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "all retries exhausted")))
}

struct TunnelPool {
    entries: Vec<(TlsStream, std::time::Instant)>,
    tls_config: Arc<rustls::ClientConfig>,
    server: String,
    server_port: u16,
    token: String,
    sni: Option<String>,
    max_size: usize,
    ttl: Duration,
    hits: u64,
}

impl TunnelPool {
    fn new(cli: &CliInner, max_size: usize, ttl: Duration) -> Self {
        Self {
            entries: Vec::new(),
            tls_config: cli.tls_config.clone(),
            server: cli.server.clone(),
            server_port: cli.server_port,
            token: cli.token.clone(),
            sni: cli.sni.clone(),
            max_size,
            ttl,
            hits: 0,
        }
    }

    async fn refill(&mut self) {
        let now = std::time::Instant::now();
        self.entries.retain(|(_, created)| now.duration_since(*created) < self.ttl);

        while self.entries.len() < self.max_size {
            match open_tunnel(
                &self.server, self.server_port, &self.token, self.tls_config.clone(),
                "0.0.0.0", 1, "tcp", self.sni.as_deref(), 0, 0.01,
            ).await {
                Ok(tls) => self.entries.push((tls, std::time::Instant::now())),
                Err(_) => break,
            }
        }
    }

    async fn acquire(&mut self, target_host: &str, target_port: u16, proto: &str) -> Option<TlsStream> {
        let now = std::time::Instant::now();
        while let Some((mut tls, created)) = self.entries.pop() {
            if now.duration_since(created) >= self.ttl {
                let _ = tls.shutdown().await;
                continue;
            }
            let mut payload = serde_json::json!({ "auth": &self.token, "host": target_host, "port": target_port });
            if proto != "tcp" { payload["proto"] = serde_json::Value::String(proto.to_string()); }
            let bootstrap = serde_json::to_string(&payload).unwrap() + "\n";
            if tls.write_all(bootstrap.as_bytes()).await.is_err() {
                continue;
            }
            if tls.flush().await.is_err() {
                continue;
            }
            let mut status_buf = vec![0u8; 64];
            match tokio::time::timeout(Duration::from_secs(10), tls.read(&mut status_buf)).await {
                Ok(Ok(n)) => {
                    let status = String::from_utf8_lossy(&status_buf[..n]);
                    if status.starts_with("OK") {
                        self.hits += 1;
                        return Some(tls);
                    }
                }
                _ => {}
            }
            let _ = tls.shutdown().await;
        }
        None
    }
}

struct PooledTunnelOpener {
    pool: Arc<Mutex<Option<TunnelPool>>>,
}

impl PooledTunnelOpener {
    async fn open(
        &self,
        cli: &CliInner,
        target_host: &str,
        target_port: u16,
        proto: &str,
    ) -> std::io::Result<TlsStream> {
        {
            let mut pool_guard = self.pool.lock().await;
            if let Some(ref mut pool) = *pool_guard {
                if let Some(tls) = pool.acquire(target_host, target_port, proto).await {
                    info!("[pool] reused warm TLS connection");
                    return Ok(tls);
                }
            }
        }
        open_tunnel(
            &cli.server, cli.server_port, &cli.token, cli.tls_config.clone(),
            target_host, target_port, proto, cli.sni.as_deref(),
            cli.connect_retries, cli.retry_delay,
        ).await
    }
}

async fn relay_bidirectional(client: TcpStream, tunnel: TlsStream) {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut tr, mut tw) = tokio::io::split(tunnel);

    let up = async {
        let mut buf = vec![0u8; PIPE_BUF_SIZE];
        let mut pending = 0usize;
        loop {
            let n = match cr.read(&mut buf).await { Ok(0) => break, Ok(n) => n, Err(_) => break };
            if tw.write_all(&buf[..n]).await.is_err() { break; }
            pending += n;
            if pending >= DRAIN_THRESHOLD { if tw.flush().await.is_err() { break; } pending = 0; }
        }
        let _ = tw.flush().await;
    };

    let down = async {
        let mut buf = vec![0u8; PIPE_BUF_SIZE];
        let mut pending = 0usize;
        loop {
            let n = match tr.read(&mut buf).await { Ok(0) => break, Ok(n) => n, Err(_) => break };
            if cw.write_all(&buf[..n]).await.is_err() { break; }
            pending += n;
            if pending >= DRAIN_THRESHOLD { if cw.flush().await.is_err() { break; } pending = 0; }
        }
        let _ = cw.flush().await;
    };

    tokio::select! { _ = up => {}, _ = down => {} }
}

struct UdpFrame {
    host: String,
    port: u16,
    data: Vec<u8>,
}

async fn read_udp_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<UdpFrame, String> {
    let mut hdr = [0u8; 4];
    reader.read_exact(&mut hdr).await.map_err(|e| format!("read hdr: {e}"))?;
    if hdr[0] != UDP_FRAME_VERSION {
        return Err("bad udp frame version".to_string());
    }
    let nlen = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if nlen == 0 || nlen > 1024 {
        return Err("bad host length".to_string());
    }
    let mut host_buf = vec![0u8; nlen];
    reader.read_exact(&mut host_buf).await.map_err(|e| format!("read host: {e}"))?;
    let host = String::from_utf8_lossy(&host_buf).to_string();
    let mut port_dlen = [0u8; 4];
    reader.read_exact(&mut port_dlen).await.map_err(|e| format!("read port_dlen: {e}"))?;
    let port = u16::from_be_bytes([port_dlen[0], port_dlen[1]]);
    let dlen = u16::from_be_bytes([port_dlen[2], port_dlen[3]]) as usize;
    if dlen > 65535 {
        return Err("bad payload length".to_string());
    }
    let mut data = vec![0u8; dlen];
    if dlen > 0 {
        reader.read_exact(&mut data).await.map_err(|e| format!("read data: {e}"))?;
    }
    Ok(UdpFrame { host, port, data })
}

async fn socks5_handshake(stream: &mut TcpStream, proxy_user: Option<&str>, proxy_pass: Option<&str>) -> std::io::Result<(String, u16, u8)> {
    let (mut r, mut w) = stream.split();
    let mut header = [0u8; 2];
    r.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported SOCKS version"));
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    r.read_exact(&mut methods).await?;

    if proxy_user.is_some() {
        if !methods.contains(&0x02) {
            w.write_all(&[SOCKS_VERSION, 0xFF]).await?; w.flush().await?;
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "auth required"));
        }
        w.write_all(&[SOCKS_VERSION, 0x02]).await?; w.flush().await?;
        let mut auth_ver = [0u8; 1]; r.read_exact(&mut auth_ver).await?;
        if auth_ver[0] != 0x01 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad auth version"));
        }
        let mut ulen_buf = [0u8; 1]; r.read_exact(&mut ulen_buf).await?;
        let mut username_buf = vec![0u8; ulen_buf[0] as usize]; r.read_exact(&mut username_buf).await?;
        let mut plen_buf = [0u8; 1]; r.read_exact(&mut plen_buf).await?;
        let mut password_buf = vec![0u8; plen_buf[0] as usize]; r.read_exact(&mut password_buf).await?;
        let username = String::from_utf8_lossy(&username_buf).to_string();
        let password = String::from_utf8_lossy(&password_buf).to_string();
        if username != proxy_user.unwrap_or("") || password != proxy_pass.unwrap_or("") {
            w.write_all(&[0x01, 0x01]).await?; w.flush().await?;
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "auth failed"));
        }
        w.write_all(&[0x01, 0x00]).await?; w.flush().await?;
    } else {
        if !methods.contains(&0x00) {
            w.write_all(&[SOCKS_VERSION, 0xFF]).await?; w.flush().await?;
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no acceptable method"));
        }
        w.write_all(&[SOCKS_VERSION, 0x00]).await?; w.flush().await?;
    }

    let mut req = [0u8; 4]; r.read_exact(&mut req).await?;
    let cmd = req[1]; let atyp = req[3];
    if req[0] != SOCKS_VERSION || (cmd != 0x01 && cmd != 0x03) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported command"));
    }

    let (host, port) = match atyp {
        0x01 => {
            let mut addr = [0u8; 4]; r.read_exact(&mut addr).await?;
            let mut pb = [0u8; 2]; r.read_exact(&mut pb).await?;
            (std::net::Ipv4Addr::from(addr).to_string(), u16::from_be_bytes(pb))
        }
        0x03 => {
            let mut lb = [0u8; 1]; r.read_exact(&mut lb).await?;
            let mut hb = vec![0u8; lb[0] as usize]; r.read_exact(&mut hb).await?;
            let mut pb = [0u8; 2]; r.read_exact(&mut pb).await?;
            (String::from_utf8_lossy(&hb).to_string(), u16::from_be_bytes(pb))
        }
        0x04 => {
            let mut addr = [0u8; 16]; r.read_exact(&mut addr).await?;
            let mut pb = [0u8; 2]; r.read_exact(&mut pb).await?;
            (std::net::Ipv6Addr::from(addr).to_string(), u16::from_be_bytes(pb))
        }
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported ATYP")),
    };
    Ok((host, port, cmd))
}

async fn handle_socks_udp_relay(
    mut client: TcpStream,
    cli: Arc<CliInner>,
    pool: Arc<PooledTunnelOpener>,
    session_id: String,
) {
    let peer = client.peer_addr().ok();
    let mut tunnel = match pool.open(&cli, "0.0.0.0", 0, "udp").await {
        Ok(s) => s,
        Err(e) => {
            warn!("[sid={session_id}] UDP tunnel open failed from {:?}: {e}", peer);
            let (_r, mut w) = client.split();
            let _ = w.write_all(&[SOCKS_VERSION, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await;
            let _ = w.flush().await;
            return;
        }
    };

    let udp_sock = match UdpSocket::bind((&cli.listen[..], 0)).await {
        Ok(s) => s,
        Err(e) => {
            warn!("[sid={session_id}] UDP bind failed: {e}");
            let _ = tunnel.shutdown().await;
            return;
        }
    };
    let sockname = udp_sock.local_addr().unwrap();
    let bind_port = sockname.port();
    let bind_ip = sockname.ip().to_string();
    let reply_ip = if bind_ip == "0.0.0.0" || bind_ip == "::" { "127.0.0.1" } else { &bind_ip };

    {
        let (_r, mut w) = client.split();
        let reply_ip_parsed: std::net::IpAddr = reply_ip.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        let mut reply = vec![SOCKS_VERSION, 0x00, 0x00];
        match reply_ip_parsed {
            std::net::IpAddr::V4(ip) => {
                reply.push(0x01);
                reply.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                reply.push(0x04);
                reply.extend_from_slice(&ip.octets());
            }
        }
        reply.extend_from_slice(&bind_port.to_be_bytes());
        let _ = w.write_all(&reply).await;
        let _ = w.flush().await;
    }

    let (mut tunnel_r, mut tunnel_w) = tokio::io::split(tunnel);
    let udp = Arc::new(udp_sock);
    let pending: Arc<Mutex<HashMap<(String, u16), Vec<(String, u16)>>>> = Arc::new(Mutex::new(HashMap::new()));
    let tunnel_write_lock = Arc::new(Mutex::new(()));

    let udp1 = udp.clone();
    let pending1 = pending.clone();
    let sid1 = session_id.clone();

    let udp_to_app = tokio::spawn(async move {
        loop {
            let frame = match read_udp_frame(&mut tunnel_r).await {
                Ok(f) => f,
                Err(_) => break,
            };
            let pkt = match socks_udp_build_reply(&frame.host, frame.port, &frame.data) {
                p => p,
            };
            let key = (frame.host.clone(), frame.port);
            let client_addr = {
                let mut p = pending1.lock().await;
                if let Some(entries) = p.get_mut(&key) {
                    if !entries.is_empty() {
                        let (h, port) = entries.remove(0);
                        if entries.is_empty() { p.remove(&key); }
                        Some((h, port))
                    } else { None }
                } else { None }
            };
            if let Some((h, port)) = client_addr {
                let addr: std::net::SocketAddr = match format!("{h}:{port}").parse() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                if let Err(e) = udp1.send_to(&pkt, addr).await {
                    debug!("[sid={sid1}] UDP sendto app failed: {e}");
                }
            }
        }
    });

    let udp2 = udp.clone();
    let pending2 = pending.clone();
    let tunnel_write_lock2 = tunnel_write_lock.clone();
    let _sid2 = session_id.clone();
    let (mut client_r, _client_w) = client.split();

    let app_to_udp = tokio::spawn(async move {
        let mut app_buf = vec![0u8; 65535];
        loop {
            let (n, src) = match udp2.recv_from(&mut app_buf).await {
                Ok(r) => r,
                Err(_) => break,
            };
            let (h, p, payload) = match socks_udp_parse_request(&app_buf[..n]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let frame = pack_udp_frame(&h, p, payload);
            let src_host = src.ip().to_string();
            let src_port = src.port();
            let key = (h.to_string(), p);
            {
                let mut p_map = pending2.lock().await;
                p_map.entry(key).or_default().push((src_host, src_port));
            }
            {
                let _lock = tunnel_write_lock2.lock().await;
                if tunnel_w.write_all(&frame).await.is_err() { break; }
                if tunnel_w.flush().await.is_err() { break; }
            }
        }
        let _ = tunnel_w.shutdown().await;
    });

    let tcp_hold = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match client_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = udp_to_app => {},
        _ = app_to_udp => {},
        _ = tcp_hold => {},
    }

    drop(udp);
}

async fn handle_socks_client(mut client: TcpStream, cli: Arc<CliInner>, pool: Arc<PooledTunnelOpener>) {
    let session_id = next_session_id(&SESSION_COUNTER);
    let peer = client.peer_addr().ok();
    set_socket_opts(&client);

    let (target_host, target_port, cmd) = match socks5_handshake(&mut client, cli.proxy_user.as_deref(), cli.proxy_pass.as_deref()).await {
        Ok(v) => v,
        Err(e) => {
            debug!("[sid={session_id}] SOCKS handshake failed from {:?}: {e}", peer);
            let (_r, mut w) = client.split();
            let rep = match e.kind() {
                std::io::ErrorKind::PermissionDenied => 0x02u8,
                _ => 0x01u8,
            };
            let _ = w.write_all(&[SOCKS_VERSION, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await;
            let _ = w.flush().await;
            return;
        }
    };

    if cmd == 0x03 {
        handle_socks_udp_relay(client, cli, pool, session_id).await;
        return;
    }

    info!("[sid={session_id}] SOCKS CONNECT from {:?} to {target_host}:{target_port}", peer);

    let tunnel = match pool.open(&cli, &target_host, target_port, "tcp").await {
        Ok(s) => s,
        Err(e) => {
            warn!("[sid={session_id}] tunnel failed: {e}");
            let (_r, mut w) = client.split();
            let rep = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => 0x05u8,
                std::io::ErrorKind::TimedOut => 0x04u8,
                std::io::ErrorKind::PermissionDenied => 0x02u8,
                _ => 0x01u8,
            };
            let _ = w.write_all(&[SOCKS_VERSION, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await;
            let _ = w.flush().await;
            return;
        }
    };

    {
        let (_r, mut w) = client.split();
        let _ = w.write_all(&[SOCKS_VERSION, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await;
        let _ = w.flush().await;
    }

    info!("[sid={session_id}] SOCKS CONNECT OK from {:?} to {target_host}:{target_port}", peer);
    relay_bidirectional(client, tunnel).await;
}

async fn handle_http_client(mut client: TcpStream, cli: Arc<CliInner>, pool: Arc<PooledTunnelOpener>) {
    let session_id = next_session_id(&SESSION_COUNTER);
    let peer = client.peer_addr().ok();
    set_socket_opts(&client);

    let mut header_buf = vec![0u8; 8192];
    let mut total = 0usize;
    loop {
        if total >= header_buf.len() { return; }
        let n = client.read(&mut header_buf[total..]).await.unwrap_or(0);
        if n == 0 { return; }
        total += n;
        if header_buf[..total].windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }

    if cli.proxy_user.is_some() && cli.proxy_pass.is_some() {
        let user = cli.proxy_user.as_deref().unwrap();
        let pass = cli.proxy_pass.as_deref().unwrap();
        let mut attempts = 0;
        loop {
            if check_http_basic_auth(&header_buf[..total], user, pass) { break; }
            attempts += 1;
            if attempts >= 2 {
                let _ = client.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"VPNProxy\"\r\nContent-Length: 0\r\n\r\n").await;
                let _ = client.flush().await;
                return;
            }
            let _ = client.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"VPNProxy\"\r\nContent-Length: 0\r\n\r\n").await;
            let _ = client.flush().await;
            total = 0;
            loop {
                if total >= header_buf.len() { return; }
                let n = client.read(&mut header_buf[total..]).await.unwrap_or(0);
                if n == 0 { return; }
                total += n;
                if header_buf[..total].windows(4).any(|w| w == b"\r\n\r\n") { break; }
            }
        }
    }

    let (target_host, target_port) = match parse_http_connect_target(&header_buf[..total]) {
        Ok(v) => v,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
            let _ = client.flush().await;
            return;
        }
    };

    debug!("[sid={session_id}] HTTP CONNECT from {:?} to {target_host}:{target_port}", peer);

    let tunnel = match pool.open(&cli, &target_host, target_port, "tcp").await {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
            let _ = client.flush().await;
            return;
        }
    };

    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
    let _ = client.flush().await;
    info!("[sid={session_id}] HTTP CONNECT OK from {:?} to {target_host}:{target_port}", peer);
    relay_bidirectional(client, tunnel).await;
}

async fn handle_tcp_line_client(mut client: TcpStream, cli: Arc<CliInner>, pool: Arc<PooledTunnelOpener>) {
    let session_id = next_session_id(&SESSION_COUNTER);
    let peer = client.peer_addr().ok();
    set_socket_opts(&client);

    let mut line_buf = vec![0u8; 4096];
    let mut total = 0usize;
    loop {
        if total >= line_buf.len() { return; }
        let n = client.read(&mut line_buf[total..]).await.unwrap_or(0);
        if n == 0 { return; }
        total += n;
        if line_buf[..total].contains(&b'\n') { break; }
    }
    let newline_pos = line_buf[..total].iter().position(|&b| b == b'\n').unwrap_or(total);
    let (target_host, target_port) = match parse_tcp_line_target(&line_buf[..newline_pos]) {
        Ok(v) => v,
        Err(e) => {
            warn!("[sid={session_id}] TCP line parse failed from {:?}: {e}", peer);
            let msg = format!("ERR {e}\n");
            let (_r, mut w) = client.split();
            let _ = w.write_all(msg.as_bytes()).await;
            let _ = w.flush().await;
            return;
        }
    };

    debug!("[sid={session_id}] TCP line target from {:?} -> {target_host}:{target_port}", peer);

    let tunnel = match pool.open(&cli, &target_host, target_port, "tcp").await {
        Ok(s) => s,
        Err(e) => {
            warn!("[sid={session_id}] TCP line tunnel failed from {:?}: {e}", peer);
            let msg = format!("ERR {e}\n");
            let (_r, mut w) = client.split();
            let _ = w.write_all(msg.as_bytes()).await;
            let _ = w.flush().await;
            return;
        }
    };

    let (_r, mut w) = client.split();
    let _ = w.write_all(b"OK\n").await;
    let _ = w.flush().await;
    info!("[sid={session_id}] TCP tunnel OK from {:?} to {target_host}:{target_port}", peer);
    relay_bidirectional(client, tunnel).await;
}

struct CliInner {
    server: String,
    server_port: u16,
    token: String,
    tls_config: Arc<rustls::ClientConfig>,
    sni: Option<String>,
    #[allow(dead_code)]
    insecure: bool,
    connect_retries: u32,
    retry_delay: f64,
    proxy_user: Option<String>,
    proxy_pass: Option<String>,
    listen: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let level = match cli.log_level.to_uppercase().as_str() {
        "DEBUG" => Level::DEBUG, "INFO" => Level::INFO,
        "WARNING" | "WARN" => Level::WARN, "ERROR" => Level::ERROR,
        _ => Level::INFO,
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(level.into()))
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let server = cli.server.clone().unwrap_or_else(|| { eprintln!("missing --server"); std::process::exit(1) });
    let token = cli.token.clone().unwrap_or_else(|| { eprintln!("missing --token"); std::process::exit(1) });
    if (cli.proxy_user.is_none()) != (cli.proxy_pass.is_none()) {
        eprintln!("--proxy-user and --proxy-pass must be specified together");
        std::process::exit(1);
    }
    let tls_config = build_tls_config(&cli);
    let inner = Arc::new(CliInner {
        server, server_port: cli.server_port, token,
        tls_config: tls_config.clone(), sni: cli.sni.clone(), insecure: cli.insecure,
        connect_retries: cli.connect_retries, retry_delay: cli.retry_delay,
        proxy_user: cli.proxy_user.clone(), proxy_pass: cli.proxy_pass.clone(),
        listen: cli.listen.clone(),
    });

    let pool_arc: Arc<Mutex<Option<TunnelPool>>> = Arc::new(Mutex::new(None));
    if cli.pool_size > 0 {
        let ttl = Duration::from_secs_f64(cli.pool_ttl);
        let mut pool_guard = pool_arc.lock().await;
        let mut pool = TunnelPool::new(&inner, cli.pool_size, ttl);
        pool.refill().await;
        info!("tunnel pool started (size={}, ttl={:.1}s)", cli.pool_size, cli.pool_ttl);
        *pool_guard = Some(pool);
        drop(pool_guard);

        let pool_refill = pool_arc.clone();
        let _inner_refill = inner.clone();
        let _pool_size = cli.pool_size;
        let _pool_ttl = cli.pool_ttl;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(300)).await;
                let mut pool_guard = pool_refill.lock().await;
                if let Some(ref mut pool) = *pool_guard {
                    pool.refill().await;
                }
            }
        });
    }
    let pool_opener = Arc::new(PooledTunnelOpener { pool: pool_arc.clone() });

    let socks_listener = TcpListener::bind((&cli.listen[..], cli.listen_port)).await.expect("cannot bind SOCKS5");
    let auth_info = if cli.proxy_user.is_some() { format!(", auth={}", cli.proxy_user.as_deref().unwrap()) } else { String::new() };
    info!("SOCKS5 proxy listening on {}:{}{}", cli.listen, cli.listen_port, auth_info);

    let socks_inner = inner.clone();
    let socks_pool = pool_opener.clone();
    let socks_handle = tokio::spawn(async move {
        loop {
            let (client, _peer) = socks_listener.accept().await.expect("accept failed");
            set_socket_opts(&client);
            let ic = socks_inner.clone();
            let p = socks_pool.clone();
            tokio::spawn(async move { handle_socks_client(client, ic, p).await; });
        }
    });

    let http_port = cli.http_port;
    let listen_for_http = cli.listen.clone();
    let inner_for_http = inner.clone();
    let pool_for_http = pool_opener.clone();

    let http_handle = tokio::spawn(async move {
        if let Some(hp) = http_port {
            let listener = TcpListener::bind((&listen_for_http[..], hp)).await.expect("cannot bind HTTP");
            info!("HTTP CONNECT proxy listening on {}:{}", listen_for_http, hp);
            loop {
                let (client, _peer) = listener.accept().await.expect("accept failed");
                set_socket_opts(&client);
                let ic = inner_for_http.clone();
                let p = pool_for_http.clone();
                tokio::spawn(async move { handle_http_client(client, ic, p).await; });
            }
        }
    });

    let tcp_line_port = cli.tcp_line_port;
    let listen_for_tcp = cli.listen.clone();
    let inner_for_tcp = inner.clone();
    let pool_for_tcp = pool_opener.clone();

    let tcp_line_handle = tokio::spawn(async move {
        if let Some(tp) = tcp_line_port {
            let listener = TcpListener::bind((&listen_for_tcp[..], tp)).await.expect("cannot bind TCP line");
            info!("TCP line proxy listening on {}:{}", listen_for_tcp, tp);
            loop {
                let (client, _peer) = listener.accept().await.expect("accept failed");
                set_socket_opts(&client);
                let ic = inner_for_tcp.clone();
                let p = pool_for_tcp.clone();
                tokio::spawn(async move { handle_tcp_line_client(client, ic, p).await; });
            }
        }
    });

    let _ = tokio::join!(socks_handle, http_handle, tcp_line_handle);
}
