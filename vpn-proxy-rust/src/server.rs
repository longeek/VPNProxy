//! VPN proxy server — Rust implementation (tokio + rustls).
//!
//! Accepts TLS connections from clients, authenticates via shared token,
//! and forwards TCP/UDP traffic to backend targets. Performance features:
//!
//! - **Rate limiting**: token-bucket (default 100 req/s, burst 20)
//! - **Connection pool**: shared via server_logic::TunnelPool
//! - **DNS cache**: uses dns_cache module (30s TTL, negative caching)
//! - **TLS session cache**: enabled by default in rustls
//!
//! Wire protocol is identical to the Python and Go implementations.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter, copy_buf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{Level, debug, info, warn};
use tracing_subscriber::EnvFilter;

use vpn_proxy::dns_cache::DnsCache;
use vpn_proxy::server_logic::{
    BootstrapInfo, RECV_BUF_SIZE, UDP_FRAME_VERSION, load_allowed_tokens, next_session_id,
    pack_udp_frame, parse_allow_cidrs, parse_bootstrap_line, peer_allowed,
};

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Token-bucket rate limiter (transplanted from Go implementation).
/// Default: 100 tokens/sec, burst of 20.
struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            max_tokens: burst,
            refill_rate: rate_per_sec,
            last_refill: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Global rate limiter instance, lazily initialized with defaults.
/// Re-initialized at startup with values from CLI args via init_rate_limiter().
static CONN_LIMITER: LazyLock<Mutex<RateLimiter>> =
    LazyLock::new(|| Mutex::new(RateLimiter::new(100.0, 20.0)));

/// Override the global rate limiter with values from CLI arguments.
/// Called once at startup after parsing command-line flags.
fn init_rate_limiter(rate_per_sec: f64, burst: u32) {
    let mut limiter = CONN_LIMITER.lock().unwrap();
    *limiter = RateLimiter::new(rate_per_sec, burst as f64);
}

/// Global DNS cache with 30s TTL (same as Go and Python implementations).
static DNS_CACHE: LazyLock<DnsCache> = LazyLock::new(|| DnsCache::new(Duration::from_secs(30)));

/// Resolve host to IP address with caching.
///
/// Checks the global DNS cache first. On cache miss, performs async DNS
/// resolution via `tokio::net::lookup_host`, prefers IPv4, and stores the
/// result (or None on failure) for the cache TTL.
async fn cached_lookup_host(host: &str) -> Option<IpAddr> {
    // Fast path: cache hit
    if let Some(ip) = DNS_CACHE.lookup(host) {
        return Some(ip);
    }
    // Cache miss: resolve and store
    let port_42 = 42u16; // arbitrary port; lookup_host requires (host, port)
    let addrs = tokio::net::lookup_host((host, port_42)).await;
    match addrs {
        Ok(mut addrs) => {
            // Prefer IPv4, fallback to any
            let ip = addrs
                .find(|a| a.is_ipv4())
                .or_else(|| addrs.next())
                .map(|a| a.ip());
            DNS_CACHE.store(host.to_string(), ip);
            ip
        }
        Err(_) => {
            // Negative cache: store failure to avoid repeated retries
            DNS_CACHE.store(host.to_string(), None);
            None
        }
    }
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
    #[arg(long, default_value_t = 100.0)]
    rate_limit: f64,
    #[arg(long, default_value_t = 20)]
    rate_burst: u32,
    #[arg(long, default_value_t = 0)]
    max_conns: usize,
}

fn load_tokens_cli(cli: &Cli) -> Vec<String> {
    load_allowed_tokens(cli.token.as_deref(), cli.tokens_file.as_deref())
}

fn set_socket_opts(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_nodelay(true);
    let _ = sock.set_recv_buffer_size(RECV_BUF_SIZE);
    let _ = sock.set_send_buffer_size(RECV_BUF_SIZE);
    // TCP keepalive (30s) to detect half-open connections (same as Go/Python)
    let _ = sock.set_keepalive(true);
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
    let _ = sock.set_tcp_keepalive(&ka);
}

#[derive(Debug)]
struct BootstrapInfo_ {
    host: String,
    port: u16,
    proto: String,
}

impl From<BootstrapInfo> for BootstrapInfo_ {
    fn from(b: BootstrapInfo) -> Self {
        BootstrapInfo_ {
            host: b.host,
            port: b.port,
            proto: b.proto,
        }
    }
}

fn parse_bootstrap(line: &str, allowed_tokens: &[String]) -> Result<BootstrapInfo_, String> {
    parse_bootstrap_line(line, allowed_tokens)
        .map(Into::into)
        .map_err(|e| e.to_string())
}

/// Per-session byte counters, shared across relay tasks via Arc.
/// Uses atomic operations for lock-free concurrent updates.
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

struct UdpFrameHeader {
    host: String,
    port: u16,
    data: Vec<u8>,
    wire_len: usize,
}

async fn read_udp_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<UdpFrameHeader, String> {
    let mut hdr = [0u8; 4];
    reader
        .read_exact(&mut hdr)
        .await
        .map_err(|e| format!("read hdr: {e}"))?;
    if hdr[0] != UDP_FRAME_VERSION {
        return Err("bad udp frame version".to_string());
    }
    let nlen = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if nlen == 0 || nlen > 1024 {
        return Err("bad udp frame host length".to_string());
    }
    let mut host_buf = vec![0u8; nlen];
    reader
        .read_exact(&mut host_buf)
        .await
        .map_err(|e| format!("read host: {e}"))?;
    let host = String::from_utf8_lossy(&host_buf).to_string();
    let mut port_dlen = [0u8; 4];
    reader
        .read_exact(&mut port_dlen)
        .await
        .map_err(|e| format!("read port_dlen: {e}"))?;
    let port = u16::from_be_bytes([port_dlen[0], port_dlen[1]]);
    let dlen = u16::from_be_bytes([port_dlen[2], port_dlen[3]]) as usize;
    if dlen > 65535 {
        return Err("bad udp frame payload length".to_string());
    }
    let mut data = vec![0u8; dlen];
    if dlen > 0 {
        reader
            .read_exact(&mut data)
            .await
            .map_err(|e| format!("read data: {e}"))?;
    }
    let wire_len = 4 + nlen + 4 + data.len();
    Ok(UdpFrameHeader {
        host,
        port,
        data,
        wire_len,
    })
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
            let ip = cached_lookup_host(send_host).await;
            let addr = match ip {
                Some(ip) => SocketAddr::new(ip, send_port),
                None => {
                    debug!("[sid={sid1}] UDP DNS lookup failed for {send_host}");
                    continue;
                }
            };
            if let Err(e) = udp1.send_to(&frame.data, addr).await {
                debug!("[sid={sid1}] UDP sendto failed: {e}");
            }
            stats1
                .upload_bytes
                .fetch_add(frame.wire_len as u64, Ordering::Relaxed);
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
                    stats2
                        .download_bytes
                        .fetch_add(frame.len() as u64, Ordering::Relaxed);
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
    info!("[sid={session_id}] UDP session closed (up={up} bytes, down={down} bytes)");
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
    let target = match tokio::time::timeout(connect_timeout, TcpStream::connect(target_addr)).await
    {
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
        host,
        port,
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
        let mut buf_reader = BufReader::with_capacity(32 * 1024, tls_r);
        let mut buf_writer = BufWriter::with_capacity(32 * 1024, target_w);
        match copy_buf(&mut buf_reader, &mut buf_writer).await {
            Ok(n) => {
                let _ = buf_writer.flush().await;
                stats_up.upload_bytes.fetch_add(n, Ordering::Relaxed);
            }
            Err(e) => {
                let _ = buf_writer.flush().await;
                if e.kind() != std::io::ErrorKind::ConnectionReset
                    && e.kind() != std::io::ErrorKind::BrokenPipe
                    && e.kind() != std::io::ErrorKind::UnexpectedEof
                {
                    debug!("[sid={sid_up}] relay error: {e}");
                }
            }
        }
    });

    let down = tokio::spawn(async move {
        let mut buf_reader = BufReader::with_capacity(32 * 1024, target_r);
        let mut buf_writer = BufWriter::with_capacity(32 * 1024, tls_w);
        match copy_buf(&mut buf_reader, &mut buf_writer).await {
            Ok(n) => {
                let _ = buf_writer.flush().await;
                stats_down.download_bytes.fetch_add(n, Ordering::Relaxed);
            }
            Err(e) => {
                let _ = buf_writer.flush().await;
                if e.kind() != std::io::ErrorKind::ConnectionReset
                    && e.kind() != std::io::ErrorKind::BrokenPipe
                {
                    debug!("[sid={sid_down}] relay error: {e}");
                }
            }
        }
    });

    let (r1, r2) = tokio::join!(up, down);
    r1.ok();
    r2.ok();

    let up_bytes = stats_final.upload_bytes.load(Ordering::Relaxed);
    let down_bytes = stats_final.download_bytes.load(Ordering::Relaxed);
    info!("[sid={session_id}] session closed (up={up_bytes} bytes, down={down_bytes} bytes)");
}

/// Shared application context passed to each connection handler.
/// Cloned cheaply via Arc for use across async tasks.
struct AppContext {
    allowed_tokens: Arc<Vec<String>>,
    allow_networks: Vec<ipnet::IpNet>,
    connect_timeout: Duration,
    bootstrap_timeout: Duration,
}

async fn handle_client(tls_stream: TlsStream, ctx: Arc<AppContext>) {
    let session_id = next_session_id(&SESSION_COUNTER);
    let peer = tls_stream.get_ref().0.peer_addr().ok();
    let stats = Arc::new(SessionStats::new());

    // Rate limiting check (transplanted from Go implementation)
    // NOTE: MutexGuard must be DROPPED before any .await to satisfy Send bound in tokio::spawn
    let rate_allowed = CONN_LIMITER.lock().unwrap().allow();
    if !rate_allowed {
        warn!(
            "[sid={session_id}] connection rate limit exceeded from {:?}",
            peer
        );
        let (_r, mut w) = tokio::io::split(tls_stream);
        let _ = w.write_all(b"ERR rate limit\n").await;
        let _ = w.flush().await;
        return;
    }

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
    })
    .await;

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

    let info = match parse_bootstrap(line_trimmed, &ctx.allowed_tokens) {
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
        let ip = match cached_lookup_host(&info.host).await {
            Some(ip) => ip,
            None => {
                warn!(
                    "[sid={session_id}] DNS lookup failed for {}:{}",
                    info.host, info.port
                );
                return;
            }
        };
        let addr = SocketAddr::new(ip, info.port);

        let _ = tls.write_all(b"OK\n").await;
        let _ = tls.flush().await;

        handle_tcp_relay(
            tls,
            addr,
            stats,
            session_id,
            ctx.connect_timeout,
            info.host,
            info.port,
        )
        .await;
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

    let cert_path = cli
        .cert
        .clone()
        .unwrap_or_else(|| "./certs/server.crt".to_string());
    let key_path = cli
        .key
        .clone()
        .unwrap_or_else(|| "./certs/server.key".to_string());
    let allowed_tokens = Arc::new(load_tokens_cli(&cli));
    let allow_networks = parse_allow_cidrs(&cli.allow_cidrs);
    let connect_timeout = Duration::from_secs_f64(cli.connect_timeout);
    let bootstrap_timeout = Duration::from_secs_f64(cli.bootstrap_timeout);
    let listen_addr = format!("{}:{}", cli.listen, cli.port);

    if allowed_tokens.is_empty() {
        eprintln!("missing token(s): set --token or --tokens-file");
        std::process::exit(1);
    }

    if !allow_networks.is_empty() {
        info!(
            "allow-cidrs enabled with {} network(s)",
            allow_networks.len()
        );
    }

    // Initialize rate limiter from CLI args
    init_rate_limiter(cli.rate_limit, cli.rate_burst);
    info!(
        "rate limit: {} req/s, burst={}",
        cli.rate_limit, cli.rate_burst
    );

    // Semaphore-based concurrency limiter (0 = unlimited, backward compatible)
    let semaphore: Option<Arc<Semaphore>> = if cli.max_conns > 0 {
        info!("max concurrent connections set to {}", cli.max_conns);
        Some(Arc::new(Semaphore::new(cli.max_conns)))
    } else {
        None
    };

    let ctx = Arc::new(AppContext {
        allowed_tokens,
        allow_networks,
        connect_timeout,
        bootstrap_timeout,
    });

    let certs: Vec<rustls::pki_types::CertificateDer<'_>> = rustls_pemfile::certs(
        &mut std::io::BufReader::new(std::fs::File::open(&cert_path).unwrap_or_else(|e| {
            eprintln!("cannot open cert file {cert_path}: {e}");
            std::process::exit(1)
        })),
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap_or_else(|e| {
        eprintln!("cannot parse cert file: {e}");
        std::process::exit(1)
    });

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(&key_path).unwrap_or_else(|e| {
            eprintln!("cannot open key file {key_path}: {e}");
            std::process::exit(1)
        }),
    ))
    .unwrap_or_else(|e| {
        eprintln!("cannot parse key file: {e}");
        std::process::exit(1)
    })
    .unwrap_or_else(|| {
        eprintln!("no key found in key file");
        std::process::exit(1)
    });

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

        // Concurrency limiting: try to acquire semaphore permit (non-blocking).
        // When limit is reached, new connections are rejected (not queued).
        let permit: Option<tokio::sync::OwnedSemaphorePermit> = match &semaphore {
            Some(sem) => match sem.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => {
                    warn!(
                        "connection limit ({}) reached, rejecting {peer}",
                        cli.max_conns
                    );
                    // Send a rejection error before closing the raw TCP stream
                    let _ = stream.writable().await;
                    let _ = stream.try_write(b"ERR busy\n");
                    continue;
                }
            },
            None => None,
        };

        let acceptor = acceptor.clone();
        let ctx = ctx.clone();

        tokio::spawn(async move {
            // RAII: _permit is held for the lifetime of this task and
            // auto-releases the semaphore slot when dropped.
            let _permit = permit;
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
