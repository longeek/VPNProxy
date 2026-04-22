use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn, Level};
use tracing_subscriber::EnvFilter;

const RECV_BUF_SIZE: usize = 256 * 1024;
const PIPE_BUF_SIZE: usize = 131072;
const DRAIN_THRESHOLD: usize = 128 * 1024;
const UDP_FRAME_VERSION: u8 = 1;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_session_id() -> String {
    let id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:08x}", id)
}

#[derive(Parser)]
#[command(name = "vpn-proxy-server", about = "TLS tunnel proxy server")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0")]
    listen: String,
    #[arg(long, default_value_t = 8443)]
    port: u16,
    #[arg(long)]
    cert: Option<String>,
    #[arg(long)]
    key: Option<String>,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    tokens_file: Option<String>,
    #[arg(long, default_value = "")]
    allow_cidrs: String,
    #[arg(long, default_value = "8")]
    connect_timeout: f64,
    #[arg(long, default_value_t = 30.0)]
    bootstrap_timeout: f64,
    #[arg(long, default_value_t = 512)]
    backlog: u32,
    #[arg(long, default_value = "INFO")]
    log_level: String,
}

fn load_allowed_tokens(cli: &Cli) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(ref t) = cli.token {
        tokens.push(t.clone());
    }
    if let Some(ref path) = cli.tokens_file {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    tokens.push(trimmed.to_string());
                }
            }
        }
    }
    tokens
}

fn parse_allow_cidrs(value: &str) -> Vec<ipnet::IpNet> {
    if value.is_empty() {
        return vec![];
    }
    value
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

fn peer_allowed(peer_ip: std::net::IpAddr, networks: &[ipnet::IpNet]) -> bool {
    if networks.is_empty() {
        return true;
    }
    networks.iter().any(|net| net.contains(&peer_ip))
}

fn set_socket_opts(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_nodelay(true);
    let _ = sock.set_recv_buffer_size(RECV_BUF_SIZE);
    let _ = sock.set_send_buffer_size(RECV_BUF_SIZE);
}

#[derive(Debug)]
struct BootstrapInfo {
    host: String,
    port: u16,
    proto: String,
}

fn parse_bootstrap_line(line: &str, allowed_tokens: &[String]) -> Result<BootstrapInfo, String> {
    let payload: serde_json::Value = serde_json::from_str(line).map_err(|e| format!("invalid json: {e}"))?;
    let token = payload.get("auth").and_then(|v| v.as_str()).ok_or("missing auth")?;
    if !allowed_tokens.iter().any(|t| t == token) {
        return Err("ERR auth".to_string());
    }
    let host = payload.get("host").and_then(|v| v.as_str()).ok_or("missing host")?.to_string();
    let port = payload.get("port").and_then(|v| v.as_u64()).ok_or("missing port")?;
    let proto = payload.get("proto").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
    if proto != "tcp" && proto != "udp" {
        return Err("invalid proto".to_string());
    }
    if port > 65535 {
        return Err("invalid port".to_string());
    }
    if proto == "tcp" && port == 0 {
        return Err("invalid port".to_string());
    }
    if proto == "udp" && host == "0.0.0.0" && port == 0 {
        // multi-destination UDP relay
    } else if proto == "udp" && port < 1 {
        return Err("invalid port".to_string());
    }
    Ok(BootstrapInfo { host, port: port as u16, proto })
}

struct SessionStats {
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
}

impl SessionStats {
    fn new() -> Self {
        Self {
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
        }
    }
}

type TlsStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

fn pack_udp_frame(host: &str, port: u16, data: &[u8]) -> Vec<u8> {
    let hb = host.as_bytes();
    let mut buf = Vec::with_capacity(4 + hb.len() + 4 + data.len());
    buf.push(UDP_FRAME_VERSION);
    buf.push(0);
    buf.extend_from_slice(&(hb.len() as u16).to_be_bytes());
    buf.extend_from_slice(hb);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

struct UdpFrameHeader {
    host: String,
    port: u16,
    data: Vec<u8>,
    wire_len: usize,
}

async fn read_udp_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<UdpFrameHeader, String> {
    let mut hdr = [0u8; 4];
    reader.read_exact(&mut hdr).await.map_err(|e| format!("read hdr: {e}"))?;
    if hdr[0] != UDP_FRAME_VERSION {
        return Err("bad udp frame version".to_string());
    }
    let nlen = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if nlen == 0 || nlen > 1024 {
        return Err("bad udp frame host length".to_string());
    }
    let mut host_buf = vec![0u8; nlen];
    reader.read_exact(&mut host_buf).await.map_err(|e| format!("read host: {e}"))?;
    let host = String::from_utf8_lossy(&host_buf).to_string();
    let mut port_dlen = [0u8; 4];
    reader.read_exact(&mut port_dlen).await.map_err(|e| format!("read port_dlen: {e}"))?;
    let port = u16::from_be_bytes([port_dlen[0], port_dlen[1]]);
    let dlen = u16::from_be_bytes([port_dlen[2], port_dlen[3]]) as usize;
    if dlen > 65535 {
        return Err("bad udp frame payload length".to_string());
    }
    let mut data = vec![0u8; dlen];
    if dlen > 0 {
        reader.read_exact(&mut data).await.map_err(|e| format!("read data: {e}"))?;
    }
    let wire_len = 4 + nlen + 4 + data.len();
    Ok(UdpFrameHeader { host, port, data, wire_len })
}

async fn run_udp_relay(
    tls_stream: TlsStream,
    stats: Arc<SessionStats>,
    host: String,
    port: u16,
    session_id: String,
) {
    let udp_sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!("[sid={session_id}] UDP bind failed: {e}");
            let (_r, mut w) = tokio::io::split(tls_stream);
            let _ = w.write_all(b"ERR connect\n").await;
            let _ = w.flush().await;
            return;
        }
    };

    let fixed_host: Option<String> = if host == "0.0.0.0" && port == 0 {
        None
    } else {
        Some(host)
    };
    let fixed_port: Option<u16> = fixed_host.as_ref().map(|_| port);

    let (mut tls_r, mut tls_w) = {
        let mut tls = tls_stream;
        let _ = tls.write_all(b"OK\n").await;
        let _ = tls.flush().await;
        tokio::io::split(tls)
    };
    let udp = Arc::new(udp_sock);

    let sid1 = session_id.clone();
    let stats1 = stats.clone();
    let fixed_host_1 = fixed_host.clone();
    let fixed_port_1 = fixed_port;
    let udp1 = udp.clone();

    let tls_to_udp = tokio::spawn(async move {
        loop {
            let frame = match read_udp_frame(&mut tls_r).await {
                Ok(f) => f,
                Err(e) => {
                    debug!("[sid={sid1}] UDP frame read error: {e}");
                    break;
                }
            };
            let send_host = fixed_host_1.as_deref().unwrap_or(&frame.host);
            let send_port = fixed_port_1.unwrap_or(frame.port);
            let addr_result = tokio::net::lookup_host((send_host, send_port)).await;
            let addr = match addr_result {
                Ok(mut addrs) => addrs.find(|a| a.is_ipv4()).or_else(|| addrs.next()),
                Err(e) => {
                    debug!("[sid={sid1}] UDP DNS lookup failed: {e}");
                    continue;
                }
            };
            let addr = match addr {
                Some(a) => a,
                None => continue,
            };
            if let Err(e) = udp1.send_to(&frame.data, addr).await {
                debug!("[sid={sid1}] UDP sendto failed: {e}");
            }
            stats1.upload_bytes.fetch_add(frame.wire_len as u64, Ordering::Relaxed);
        }
    });

    let sid2 = session_id.clone();
    let stats2 = stats.clone();
    let udp2 = udp.clone();

    let udp_to_tls = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match udp2.recv_from(&mut buf).await {
                Ok((n, src_addr)) => {
                    let src_host = src_addr.ip().to_string();
                    let src_port = src_addr.port();
                    let frame = pack_udp_frame(&src_host, src_port, &buf[..n]);
                    if let Err(e) = tls_w.write_all(&frame).await {
                        debug!("[sid={sid2}] UDP frame write error: {e}");
                        break;
                    }
                    if let Err(e) = tls_w.flush().await {
                        debug!("[sid={sid2}] UDP flush error: {e}");
                        break;
                    }
                    stats2.download_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    debug!("[sid={sid2}] UDP recv error: {e}");
                    break;
                }
            }
        }
    });

    let _ = tokio::join!(tls_to_udp, udp_to_tls);
    drop(udp);

    let up = stats.upload_bytes.load(Ordering::Relaxed);
    let down = stats.download_bytes.load(Ordering::Relaxed);
    info!(
        "[sid={session_id}] UDP session closed (up={up} bytes, down={down} bytes)"
    );
}

async fn handle_tcp_relay(
    tls_stream: TlsStream,
    target_addr: SocketAddr,
    stats: Arc<SessionStats>,
    session_id: String,
    connect_timeout: Duration,
    host: String,
    port: u16,
) {
    let t0 = std::time::Instant::now();
    let target = match tokio::time::timeout(connect_timeout, TcpStream::connect(target_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("[sid={session_id}] backend connect failed to {target_addr}: {e}");
            return;
        }
        Err(_) => {
            warn!("[sid={session_id}] backend connect timeout to {target_addr}");
            return;
        }
    };
    let t1 = std::time::Instant::now();
    set_socket_opts(&target);
    debug!(
        "[sid={session_id}] backend connect timing: {:.0}ms to {}:{} (timeout={:.1}s)",
        (t1 - t0).as_secs_f64() * 1000.0,
        host, port,
        connect_timeout.as_secs_f64(),
    );

    let (tls_r, tls_w) = tokio::io::split(tls_stream);
    let (target_r, target_w) = target.into_split();

    let stats_up = stats.clone();
    let stats_down = stats.clone();
    let stats_final = stats;
    let sid_up = session_id.clone();
    let sid_down = session_id.clone();

    let up = tokio::spawn(async move {
        let mut tls_r = tokio::io::BufReader::with_capacity(PIPE_BUF_SIZE, tls_r);
        let mut target_w = tokio::io::BufWriter::with_capacity(PIPE_BUF_SIZE, target_w);
        let mut buf = vec![0u8; PIPE_BUF_SIZE];
        let mut pending = 0usize;
        let mut acc = 0u64;
        loop {
            let n = match tls_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::ConnectionReset
                        && e.kind() != std::io::ErrorKind::BrokenPipe
                        && e.kind() != std::io::ErrorKind::UnexpectedEof
                    {
                        debug!("[sid={sid_up}] tls read: {e}");
                    }
                    break;
                }
            };
            if let Err(e) = target_w.write_all(&buf[..n]).await {
                if e.kind() != std::io::ErrorKind::BrokenPipe {
                    debug!("[sid={sid_up}] target write: {e}");
                }
                break;
            }
            pending += n;
            acc += n as u64;
            if pending >= DRAIN_THRESHOLD {
                if let Err(e) = target_w.flush().await {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        debug!("[sid={sid_up}] target flush: {e}");
                    }
                    break;
                }
                pending = 0;
                stats_up.upload_bytes.fetch_add(acc, Ordering::Relaxed);
                acc = 0;
            }
        }
        if acc > 0 {
            stats_up.upload_bytes.fetch_add(acc, Ordering::Relaxed);
        }
    });

    let down = tokio::spawn(async move {
        let mut target_r = tokio::io::BufReader::with_capacity(PIPE_BUF_SIZE, target_r);
        let mut tls_w = tokio::io::BufWriter::with_capacity(PIPE_BUF_SIZE, tls_w);
        let mut buf = vec![0u8; PIPE_BUF_SIZE];
        let mut pending = 0usize;
        let mut acc = 0u64;
        loop {
            let n = match target_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::ConnectionReset
                        && e.kind() != std::io::ErrorKind::BrokenPipe
                    {
                        debug!("[sid={sid_down}] target read: {e}");
                    }
                    break;
                }
            };
            if let Err(e) = tls_w.write_all(&buf[..n]).await {
                if e.kind() != std::io::ErrorKind::BrokenPipe {
                    debug!("[sid={sid_down}] tls write: {e}");
                }
                break;
            }
            pending += n;
            acc += n as u64;
            if pending >= DRAIN_THRESHOLD {
                if let Err(e) = tls_w.flush().await {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        debug!("[sid={sid_down}] tls flush: {e}");
                    }
                    break;
                }
                pending = 0;
                stats_down.download_bytes.fetch_add(acc, Ordering::Relaxed);
                acc = 0;
            }
        }
        if acc > 0 {
            stats_down.download_bytes.fetch_add(acc, Ordering::Relaxed);
        }
    });

    let (r1, r2) = tokio::join!(up, down);
    r1.ok();
    r2.ok();

    let up_bytes = stats_final.upload_bytes.load(Ordering::Relaxed);
    let down_bytes = stats_final.download_bytes.load(Ordering::Relaxed);
    info!(
        "[sid={session_id}] session closed (up={up_bytes} bytes, down={down_bytes} bytes)"
    );
}

struct AppContext {
    allowed_tokens: Arc<Vec<String>>,
    allow_networks: Vec<ipnet::IpNet>,
    connect_timeout: Duration,
    bootstrap_timeout: Duration,
}

async fn handle_client(tls_stream: TlsStream, ctx: Arc<AppContext>) {
    let session_id = next_session_id();
    let peer = tls_stream.get_ref().0.peer_addr().ok();
    let stats = Arc::new(SessionStats::new());

    if let Some(ref peer_addr) = peer {
        if !peer_allowed(peer_addr.ip(), &ctx.allow_networks) {
            warn!("[sid={session_id}] peer not in allow-cidrs: {peer_addr}");
            let (_r, mut w) = tokio::io::split(tls_stream);
            let _ = w.write_all(b"ERR connect\n").await;
            let _ = w.flush().await;
            return;
        }
    }

    let mut tls = tls_stream;
    let mut line_buf = vec![0u8; 4096];
    let mut total_read = 0usize;

    let read_result = tokio::time::timeout(ctx.bootstrap_timeout, async {
        loop {
            if total_read >= line_buf.len() {
                break Err("bootstrap line too long".to_string());
            }
            match tls.read(&mut line_buf[total_read..]).await {
                Ok(0) => break Err("connection closed".to_string()),
                Ok(n) => {
                    total_read += n;
                    if line_buf[..total_read].contains(&b'\n') {
                        break Ok(total_read);
                    }
                    continue;
                }
                Err(e) => break Err(format!("read error: {e}")),
            }
        }
    }).await;

    let n = match read_result {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            debug!("[sid={session_id}] bootstrap read failed: {e}");
            return;
        }
        Err(_) => {
            warn!("[sid={session_id}] bootstrap timeout");
            return;
        }
    };

    let newline_pos = line_buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let line = String::from_utf8_lossy(&line_buf[..newline_pos]);
    let line_trimmed = line.trim_end_matches('\r');

    let info = match parse_bootstrap_line(line_trimmed, &ctx.allowed_tokens) {
        Ok(i) => i,
        Err(e) => {
            warn!("[sid={session_id}] bootstrap error from {:?}: {e}", peer);
            if e == "ERR auth" {
                let _ = tls.write_all(b"ERR auth\n").await;
            } else {
                let msg = format!("ERR {e}\n");
                let _ = tls.write_all(msg.as_bytes()).await;
            }
            let _ = tls.flush().await;
            return;
        }
    };

    info!(
        "[sid={session_id}] accepted tunnel from {:?} to {}:{} ({})",
        peer, info.host, info.port, info.proto
    );

    if info.proto == "udp" {
        run_udp_relay(tls, stats, info.host, info.port, session_id).await;
    } else {
        let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((&info.host[..], info.port)).await {
            Ok(a) => a.collect(),
            Err(e) => {
                warn!("[sid={session_id}] DNS lookup failed for {}:{}: {e}", info.host, info.port);
                return;
            }
        };
        let addr = match addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first()) {
            Some(a) => *a,
            None => {
                warn!("[sid={session_id}] no address found for {}:{}", info.host, info.port);
                return;
            }
        };

        let _ = tls.write_all(b"OK\n").await;
        let _ = tls.flush().await;

        handle_tcp_relay(tls, addr, stats, session_id, ctx.connect_timeout, info.host, info.port).await;
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let level = match cli.log_level.to_uppercase().as_str() {
        "DEBUG" => Level::DEBUG,
        "INFO" => Level::INFO,
        "WARNING" | "WARN" => Level::WARN,
        "ERROR" => Level::ERROR,
        _ => Level::INFO,
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(level.into()))
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cert_path = cli.cert.clone().unwrap_or_else(|| "./certs/server.crt".to_string());
    let key_path = cli.key.clone().unwrap_or_else(|| "./certs/server.key".to_string());
    let allowed_tokens = Arc::new(load_allowed_tokens(&cli));
    let allow_networks = parse_allow_cidrs(&cli.allow_cidrs);
    let connect_timeout = Duration::from_secs_f64(cli.connect_timeout);
    let bootstrap_timeout = Duration::from_secs_f64(cli.bootstrap_timeout);
    let listen_addr = format!("{}:{}", cli.listen, cli.port);

    if allowed_tokens.is_empty() {
        eprintln!("missing token(s): set --token or --tokens-file");
        std::process::exit(1);
    }

    if !allow_networks.is_empty() {
        info!("allow-cidrs enabled with {} network(s)", allow_networks.len());
    }

    let ctx = Arc::new(AppContext {
        allowed_tokens,
        allow_networks,
        connect_timeout,
        bootstrap_timeout,
    });

    let certs: Vec<rustls::pki_types::CertificateDer<'_>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(&cert_path).unwrap_or_else(|e| { eprintln!("cannot open cert file {cert_path}: {e}"); std::process::exit(1) })
    )).collect::<Result<Vec<_>, _>>().unwrap_or_else(|e| { eprintln!("cannot parse cert file: {e}"); std::process::exit(1) });

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(&key_path).unwrap_or_else(|e| { eprintln!("cannot open key file {key_path}: {e}"); std::process::exit(1) })
    )).unwrap_or_else(|e| { eprintln!("cannot parse key file: {e}"); std::process::exit(1) })
      .unwrap_or_else(|| { eprintln!("no key found in key file"); std::process::exit(1) });

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("bad cert/key");

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&listen_addr).await.expect("cannot bind");
    info!("server started on {}", listen_addr);

    loop {
        let (stream, peer) = listener.accept().await.expect("accept failed");
        set_socket_opts(&stream);
        debug!("new connection from {}", peer);

        let acceptor = acceptor.clone();
        let ctx = ctx.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    handle_client(tls_stream, ctx).await;
                }
                Err(e) => {
                    warn!("TLS accept error from {peer}: {e}");
                }
            }
        });
    }
}
