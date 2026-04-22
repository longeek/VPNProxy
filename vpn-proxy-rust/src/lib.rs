pub mod server_logic {
    use std::net::IpAddr;

    pub const RECV_BUF_SIZE: usize = 256 * 1024;
    pub const PIPE_BUF_SIZE: usize = 131072;
    pub const DRAIN_THRESHOLD: usize = 128 * 1024;
    pub const UDP_FRAME_VERSION: u8 = 1;

    #[derive(Debug, Clone, PartialEq)]
    pub struct BootstrapInfo {
        pub host: String,
        pub port: u16,
        pub proto: String,
    }

    pub fn load_allowed_tokens(token: Option<&str>, tokens_file: Option<&str>) -> Vec<String> {
        let mut tokens = Vec::new();
        if let Some(t) = token {
            tokens.push(t.to_string());
        }
        if let Some(path) = tokens_file {
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

    pub fn parse_allow_cidrs(value: &str) -> Vec<ipnet::IpNet> {
        if value.is_empty() {
            return vec![];
        }
        value
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    }

    pub fn peer_allowed(peer_ip: IpAddr, networks: &[ipnet::IpNet]) -> bool {
        if networks.is_empty() {
            return true;
        }
        networks.iter().any(|net| net.contains(&peer_ip))
    }

    pub fn parse_bootstrap_line(line: &str, allowed_tokens: &[String]) -> Result<BootstrapInfo, String> {
        let payload: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("invalid json: {e}"))?;
        let token = payload
            .get("auth")
            .and_then(|v| v.as_str())
            .ok_or("missing auth")?;
        if !allowed_tokens.iter().any(|t| t == token) {
            return Err("ERR auth".to_string());
        }
        let host = payload
            .get("host")
            .and_then(|v| v.as_str())
            .ok_or("missing host")?
            .to_string();
        let port = payload
            .get("port")
            .and_then(|v| v.as_u64())
            .ok_or("missing port")?;
        let proto = payload
            .get("proto")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp")
            .to_string();
        if proto != "tcp" && proto != "udp" {
            return Err("invalid proto".to_string());
        }
        if port > 65535 {
            return Err("invalid port".to_string());
        }
        if proto == "tcp" && port == 0 {
            return Err("invalid port".to_string());
        }
        Ok(BootstrapInfo {
            host,
            port: port as u16,
            proto,
        })
    }

    pub fn pack_udp_frame(host: &str, port: u16, data: &[u8]) -> Vec<u8> {
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

    #[derive(Debug, PartialEq)]
    pub struct UdpFrameHeader {
        pub host: String,
        pub port: u16,
        pub data: Vec<u8>,
        pub wire_len: usize,
    }

    pub fn read_udp_frame_from_slice(buf: &[u8]) -> Result<UdpFrameHeader, String> {
        if buf.len() < 4 {
            return Err("buffer too short for header".to_string());
        }
        if buf[0] != UDP_FRAME_VERSION {
            return Err("bad udp frame version".to_string());
        }
        let nlen = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if nlen == 0 || nlen > 1024 {
            return Err("bad udp frame host length".to_string());
        }
        if buf.len() < 4 + nlen + 4 {
            return Err("buffer too short for host+port_dlen".to_string());
        }
        let host = String::from_utf8_lossy(&buf[4..4 + nlen]).to_string();
        let off = 4 + nlen;
        let port = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let dlen = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        if dlen > 65535 {
            return Err("bad udp frame payload length".to_string());
        }
        if buf.len() < off + 4 + dlen {
            return Err("buffer too short for payload".to_string());
        }
        let data = buf[off + 4..off + 4 + dlen].to_vec();
        let wire_len = off + 4 + dlen;
        Ok(UdpFrameHeader {
            host,
            port,
            data,
            wire_len,
        })
    }

    pub fn next_session_id(counter: &std::sync::atomic::AtomicU64) -> String {
        let id = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{:08x}", id)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use std::sync::atomic::AtomicU64;

        #[test]
        fn test_load_allowed_tokens_token_only() {
            let tokens = load_allowed_tokens(Some("abc123"), None);
            assert_eq!(tokens, vec!["abc123"]);
        }

        #[test]
        fn test_load_allowed_tokens_file_only() {
            let dir = std::env::temp_dir().join("vpn_test_tokens.txt");
            std::fs::write(&dir, "token1\ntoken2\n# comment\n\ntoken3\n").unwrap();
            let tokens = load_allowed_tokens(None, dir.to_str());
            assert_eq!(tokens, vec!["token1", "token2", "token3"]);
            let _ = std::fs::remove_file(&dir);
        }

        #[test]
        fn test_load_allowed_tokens_both() {
            let dir = std::env::temp_dir().join("vpn_test_tokens2.txt");
            std::fs::write(&dir, "file_token\n").unwrap();
            let tokens = load_allowed_tokens(Some("arg_token"), dir.to_str());
            assert_eq!(tokens, vec!["arg_token", "file_token"]);
            let _ = std::fs::remove_file(&dir);
        }

        #[test]
        fn test_load_allowed_tokens_none() {
            let tokens = load_allowed_tokens(None, None);
            assert!(tokens.is_empty());
        }

        #[test]
        fn test_load_allowed_tokens_missing_file() {
            let tokens = load_allowed_tokens(None, Some("/nonexistent/path/tokens.txt"));
            assert!(tokens.is_empty());
        }

        #[test]
        fn test_parse_allow_cidrs_empty() {
            assert!(parse_allow_cidrs("").is_empty());
        }

        #[test]
        fn test_parse_allow_cidrs_single() {
            let nets = parse_allow_cidrs("10.0.0.0/8");
            assert_eq!(nets.len(), 1);
            assert!(nets[0].contains(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
            assert!(!nets[0].contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        }

        #[test]
        fn test_parse_allow_cidrs_multiple() {
            let nets = parse_allow_cidrs("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16");
            assert_eq!(nets.len(), 3);
        }

        #[test]
        fn test_parse_allow_cidrs_invalid_ignored() {
            let nets = parse_allow_cidrs("10.0.0.0/8,not-a-cidr,192.168.0.0/16");
            assert_eq!(nets.len(), 2);
        }

        #[test]
        fn test_peer_allowed_empty_networks() {
            assert!(peer_allowed(
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                &[]
            ));
        }

        #[test]
        fn test_peer_allowed_in_network() {
            let nets = parse_allow_cidrs("10.0.0.0/8");
            assert!(peer_allowed(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                &nets
            ));
        }

        #[test]
        fn test_peer_allowed_not_in_network() {
            let nets = parse_allow_cidrs("10.0.0.0/8");
            assert!(!peer_allowed(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                &nets
            ));
        }

        #[test]
        fn test_peer_allowed_ipv6() {
            let nets = parse_allow_cidrs("::1/128,fd00::/8");
            assert!(peer_allowed(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
                &nets
            ));
            assert!(peer_allowed(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                &nets
            ));
            assert!(!peer_allowed(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                &nets
            ));
        }

        #[test]
        fn test_parse_bootstrap_line_valid_tcp() {
            let tokens = vec!["mytoken".to_string()];
            let info = parse_bootstrap_line(
                r#"{"auth":"mytoken","host":"example.com","port":443}"#,
                &tokens,
            )
            .unwrap();
            assert_eq!(info.host, "example.com");
            assert_eq!(info.port, 443);
            assert_eq!(info.proto, "tcp");
        }

        #[test]
        fn test_parse_bootstrap_line_valid_udp() {
            let tokens = vec!["tok".to_string()];
            let info = parse_bootstrap_line(
                r#"{"auth":"tok","host":"8.8.8.8","port":53,"proto":"udp"}"#,
                &tokens,
            )
            .unwrap();
            assert_eq!(info.proto, "udp");
        }

        #[test]
        fn test_parse_bootstrap_line_bad_auth() {
            let tokens = vec!["goodtoken".to_string()];
            let result = parse_bootstrap_line(
                r#"{"auth":"badtoken","host":"example.com","port":443}"#,
                &tokens,
            );
            assert_eq!(result.unwrap_err(), "ERR auth");
        }

        #[test]
        fn test_parse_bootstrap_line_missing_auth() {
            let tokens = vec!["tok".to_string()];
            let result = parse_bootstrap_line(
                r#"{"host":"example.com","port":443}"#,
                &tokens,
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_bootstrap_line_missing_host() {
            let tokens = vec!["tok".to_string()];
            let result = parse_bootstrap_line(
                r#"{"auth":"tok","port":443}"#,
                &tokens,
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_bootstrap_line_missing_port() {
            let tokens = vec!["tok".to_string()];
            let result = parse_bootstrap_line(
                r#"{"auth":"tok","host":"example.com"}"#,
                &tokens,
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_bootstrap_line_invalid_json() {
            let tokens = vec!["tok".to_string()];
            let result = parse_bootstrap_line("not json", &tokens);
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_bootstrap_line_invalid_proto() {
            let tokens = vec!["tok".to_string()];
            let result = parse_bootstrap_line(
                r#"{"auth":"tok","host":"x","port":80,"proto":"icmp"}"#,
                &tokens,
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_bootstrap_line_port_zero_tcp() {
            let tokens = vec!["tok".to_string()];
            let result = parse_bootstrap_line(
                r#"{"auth":"tok","host":"x","port":0,"proto":"tcp"}"#,
                &tokens,
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_bootstrap_line_port_overflow() {
            let tokens = vec!["tok".to_string()];
            let result = parse_bootstrap_line(
                r#"{"auth":"tok","host":"x","port":70000}"#,
                &tokens,
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_pack_and_parse_udp_frame() {
            let packed = pack_udp_frame("example.com", 53, b"hello");
            let parsed = read_udp_frame_from_slice(&packed).unwrap();
            assert_eq!(parsed.host, "example.com");
            assert_eq!(parsed.port, 53);
            assert_eq!(parsed.data, b"hello");
            assert_eq!(parsed.wire_len, packed.len());
        }

        #[test]
        fn test_pack_udp_frame_empty_data() {
            let packed = pack_udp_frame("10.0.0.1", 1234, b"");
            let parsed = read_udp_frame_from_slice(&packed).unwrap();
            assert_eq!(parsed.host, "10.0.0.1");
            assert_eq!(parsed.port, 1234);
            assert!(parsed.data.is_empty());
        }

        #[test]
        fn test_read_udp_frame_bad_version() {
            let mut packed = pack_udp_frame("x", 1, b"d");
            packed[0] = 99;
            let result = read_udp_frame_from_slice(&packed);
            assert!(result.is_err());
        }

        #[test]
        fn test_read_udp_frame_too_short() {
            let result = read_udp_frame_from_slice(&[0, 0, 0, 0]);
            assert!(result.is_err());
        }

        #[test]
        fn test_read_udp_frame_zero_host_len() {
            let buf = vec![UDP_FRAME_VERSION, 0, 0, 0, 0, 0, 0, 0];
            let result = read_udp_frame_from_slice(&buf);
            assert!(result.is_err());
        }

        #[test]
        fn test_next_session_id() {
            let counter = AtomicU64::new(42);
            assert_eq!(next_session_id(&counter), "0000002a");
            assert_eq!(next_session_id(&counter), "0000002b");
        }

        #[test]
        fn test_parse_bootstrap_line_udp_zero_zero() {
            let tokens = vec!["tok".to_string()];
            let info = parse_bootstrap_line(
                r#"{"auth":"tok","host":"0.0.0.0","port":0,"proto":"udp"}"#,
                &tokens,
            )
            .unwrap();
            assert_eq!(info.proto, "udp");
            assert_eq!(info.host, "0.0.0.0");
            assert_eq!(info.port, 0);
        }

        #[test]
        fn test_pack_udp_frame_large_data() {
            let data = vec![0xAB; 1000];
            let packed = pack_udp_frame("host", 80, &data);
            let parsed = read_udp_frame_from_slice(&packed).unwrap();
            assert_eq!(parsed.data.len(), 1000);
            assert_eq!(parsed.data, data);
        }
    }
}

pub mod client_logic {
    pub const SOCKS_VERSION: u8 = 5;
    pub const UDP_FRAME_VERSION: u8 = 1;

    pub fn socks_udp_parse_request(packet: &[u8]) -> Result<(String, u16, &[u8]), String> {
        if packet.len() < 10 {
            return Err("short socks udp packet".to_string());
        }
        if packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
            return Err("bad socks udp header".to_string());
        }
        let atyp = packet[3];
        let (host, off) = match atyp {
            0x01 => {
                if packet.len() < 10 {
                    return Err("short ipv4".to_string());
                }
                let addr: [u8; 4] = packet[4..8]
                    .try_into()
                    .map_err(|_| "ipv4 parse")?;
                (std::net::Ipv4Addr::from(addr).to_string(), 8)
            }
            0x03 => {
                let ln = packet[4] as usize;
                if packet.len() < 5 + ln + 2 {
                    return Err("short domain".to_string());
                }
                let host = String::from_utf8_lossy(&packet[5..5 + ln]).to_string();
                (host, 5 + ln)
            }
            0x04 => {
                if packet.len() < 20 {
                    return Err("short ipv6".to_string());
                }
                let addr: [u8; 16] = packet[4..20]
                    .try_into()
                    .map_err(|_| "ipv6 parse")?;
                (std::net::Ipv6Addr::from(addr).to_string(), 20)
            }
            _ => return Err("unsupported atyp".to_string()),
        };
        if packet.len() < off + 2 {
            return Err("short port".to_string());
        }
        let port = u16::from_be_bytes([packet[off], packet[off + 1]]);
        Ok((host, port, &packet[off + 2..]))
    }

    pub fn socks_udp_build_reply(host: &str, port: u16, data: &[u8]) -> Vec<u8> {
        let addr: Result<std::net::IpAddr, _> = host.parse();
        match addr {
            Ok(std::net::IpAddr::V4(ip)) => {
                let mut buf = Vec::with_capacity(4 + 4 + 2 + data.len());
                buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
                buf.extend_from_slice(data);
                buf
            }
            Ok(std::net::IpAddr::V6(ip)) => {
                let mut buf = Vec::with_capacity(4 + 16 + 2 + data.len());
                buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
                buf.extend_from_slice(data);
                buf
            }
            Err(_) => {
                let hb = host.as_bytes();
                let mut buf = Vec::with_capacity(4 + 1 + hb.len() + 2 + data.len());
                buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]);
                buf.push(hb.len() as u8);
                buf.extend_from_slice(hb);
                buf.extend_from_slice(&port.to_be_bytes());
                buf.extend_from_slice(data);
                buf
            }
        }
    }

    pub fn parse_http_connect_target(header: &[u8]) -> std::io::Result<(String, u16)> {
        let s = String::from_utf8_lossy(header);
        let first_line = s
            .lines()
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "empty request"))?;
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() < 3 || !parts[0].eq_ignore_ascii_case("CONNECT") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not CONNECT",
            ));
        }
        let target = parts[1];
        let sep = target
            .rfind(':')
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad target"))?;
        let host = target[..sep].to_string();
        let port: u16 = target[sep + 1..]
            .parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad port"))?;
        Ok((host, port))
    }

    pub fn check_http_basic_auth(header: &[u8], user: &str, pass: &str) -> bool {
        let s = String::from_utf8_lossy(header);
        for line in s.lines() {
            if line.to_lowercase().starts_with("proxy-authorization:") {
                let value = line.split(':').nth(1).unwrap_or("").trim();
                if value.to_lowercase().starts_with("basic ") {
                    let b64 = value[6..].trim();
                    if let Ok(decoded) =
                        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                    {
                        if let Ok(ds) = String::from_utf8(decoded) {
                            let parts: Vec<&str> = ds.splitn(2, ':').collect();
                            if parts.len() == 2 && parts[0] == user && parts[1] == pass {
                                return true;
                            }
                        }
                    }
                }
                break;
            }
        }
        false
    }

    pub fn parse_tcp_line_target(line: &[u8]) -> std::io::Result<(String, u16)> {
        let s = String::from_utf8_lossy(line).trim().to_string();
        if s.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "empty target",
            ));
        }
        if let Some(sep) = s.rfind(':') {
            let host = s[..sep].trim().to_string();
            let port_s = s[sep + 1..].trim();
            let port: u16 = port_s
                .parse()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad port"))?;
            if host.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "empty host",
                ));
            }
            if port == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bad port",
                ));
            }
            return Ok((host, port));
        }
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() == 2 {
            let host = parts[0].to_string();
            let port: u16 = parts[1]
                .parse()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad port"))?;
            if port == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bad port",
                ));
            }
            return Ok((host, port));
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected host:port",
        ))
    }

    pub fn pack_udp_frame(host: &str, port: u16, data: &[u8]) -> Vec<u8> {
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

    pub fn read_udp_frame_from_slice(buf: &[u8]) -> Result<UdpFrame, String> {
        if buf.len() < 4 {
            return Err("buffer too short".to_string());
        }
        if buf[0] != UDP_FRAME_VERSION {
            return Err("bad udp frame version".to_string());
        }
        let nlen = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if nlen == 0 || nlen > 1024 {
            return Err("bad host length".to_string());
        }
        if buf.len() < 4 + nlen + 4 {
            return Err("buffer too short for host+port_dlen".to_string());
        }
        let host = String::from_utf8_lossy(&buf[4..4 + nlen]).to_string();
        let off = 4 + nlen;
        let port = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let dlen = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        if dlen > 65535 {
            return Err("bad payload length".to_string());
        }
        if buf.len() < off + 4 + dlen {
            return Err("buffer too short for payload".to_string());
        }
        let data = buf[off + 4..off + 4 + dlen].to_vec();
        Ok(UdpFrame {
            host,
            port,
            data,
        })
    }

    #[derive(Debug, PartialEq)]
    pub struct UdpFrame {
        pub host: String,
        pub port: u16,
        pub data: Vec<u8>,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_socks_udp_parse_ipv4() {
            let mut pkt = vec![0x00, 0x00, 0x00, 0x01]; // RSV, FRAG, ATYP=IPv4
            pkt.extend_from_slice(&[10, 0, 0, 1]); // IP
            pkt.extend_from_slice(&[0x00, 0x35]); // port 53
            pkt.extend_from_slice(b"hello");
            let (host, port, data) = socks_udp_parse_request(&pkt).unwrap();
            assert_eq!(host, "10.0.0.1");
            assert_eq!(port, 53);
            assert_eq!(data, b"hello");
        }

        #[test]
        fn test_socks_udp_parse_domain() {
            let mut pkt = vec![0x00, 0x00, 0x00, 0x03]; // RSV, FRAG, ATYP=domain
            pkt.push(11); // domain length
            pkt.extend_from_slice(b"example.com");
            pkt.extend_from_slice(&[0x01, 0xBB]); // port 443
            pkt.extend_from_slice(b"data");
            let (host, port, data) = socks_udp_parse_request(&pkt).unwrap();
            assert_eq!(host, "example.com");
            assert_eq!(port, 443);
            assert_eq!(data, b"data");
        }

        #[test]
        fn test_socks_udp_parse_ipv6() {
            let mut pkt = vec![0x00, 0x00, 0x00, 0x04]; // RSV, FRAG, ATYP=IPv6
            let ip: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            pkt.extend_from_slice(&ip);
            pkt.extend_from_slice(&[0x00, 0x50]); // port 80
            pkt.extend_from_slice(b"v6data");
            let (host, port, data) = socks_udp_parse_request(&pkt).unwrap();
            assert!(host.contains("2001:db8"));
            assert_eq!(port, 80);
            assert_eq!(data, b"v6data");
        }

        #[test]
        fn test_socks_udp_parse_bad_header() {
            let pkt = vec![0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            assert!(socks_udp_parse_request(&pkt).is_err());
        }

        #[test]
        fn test_socks_udp_parse_too_short() {
            assert!(socks_udp_parse_request(&[0; 5]).is_err());
        }

        #[test]
        fn test_socks_udp_parse_unsupported_atyp() {
            let pkt = vec![0x00, 0x00, 0x00, 0x05, 0, 0, 0, 0, 0, 0];
            assert!(socks_udp_parse_request(&pkt).is_err());
        }

        #[test]
        fn test_socks_udp_parse_short_ipv4() {
            let pkt = vec![0x00, 0x00, 0x00, 0x01, 10, 0]; // only 2 bytes of IP
            assert!(socks_udp_parse_request(&pkt).is_err());
        }

        #[test]
        fn test_socks_udp_parse_short_domain() {
            let mut pkt = vec![0x00, 0x00, 0x00, 0x03, 20]; // domain length 20 but no data
            pkt.extend_from_slice(&[0; 5]);
            assert!(socks_udp_parse_request(&pkt).is_err());
        }

        #[test]
        fn test_socks_udp_build_reply_ipv4() {
            let reply = socks_udp_build_reply("10.0.0.1", 80, b"abc");
            assert_eq!(reply[0..4], [0x00, 0x00, 0x00, 0x01]);
            assert_eq!(reply[4..8], [10, 0, 0, 1]);
            assert_eq!(&reply[10..], b"abc");
        }

        #[test]
        fn test_socks_udp_build_reply_ipv6() {
            let reply = socks_udp_build_reply("::1", 443, b"x");
            assert_eq!(reply[0..4], [0x00, 0x00, 0x00, 0x04]);
            assert_eq!(reply.len(), 4 + 16 + 2 + 1);
        }

        #[test]
        fn test_socks_udp_build_reply_domain() {
            let reply = socks_udp_build_reply("example.com", 53, b"dns");
            assert_eq!(reply[0..4], [0x00, 0x00, 0x00, 0x03]);
            assert_eq!(reply[4], 11); // domain length
            assert_eq!(&reply[5..16], b"example.com");
            assert_eq!(&reply[18..], b"dns");
        }

        #[test]
        fn test_socks_udp_roundtrip_ipv4() {
            let reply = socks_udp_build_reply("192.168.1.1", 8080, b"payload");
            let (host, port, data) = socks_udp_parse_request(&reply).unwrap();
            assert_eq!(host, "192.168.1.1");
            assert_eq!(port, 8080);
            assert_eq!(data, b"payload");
        }

        #[test]
        fn test_socks_udp_roundtrip_ipv6() {
            let reply = socks_udp_build_reply("::1", 443, b"v6");
            let (host, port, data) = socks_udp_parse_request(&reply).unwrap();
            assert_eq!(port, 443);
            assert_eq!(data, b"v6");
        }

        #[test]
        fn test_socks_udp_roundtrip_domain() {
            let reply = socks_udp_build_reply("test.example.com", 993, b"imap");
            let (host, port, data) = socks_udp_parse_request(&reply).unwrap();
            assert_eq!(host, "test.example.com");
            assert_eq!(port, 993);
            assert_eq!(data, b"imap");
        }

        #[test]
        fn test_parse_http_connect_valid() {
            let header = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
            let (host, port) = parse_http_connect_target(header).unwrap();
            assert_eq!(host, "example.com");
            assert_eq!(port, 443);
        }

        #[test]
        fn test_parse_http_connect_lowercase() {
            let header = b"connect google.com:80 HTTP/1.1\r\n\r\n";
            let (host, port) = parse_http_connect_target(header).unwrap();
            assert_eq!(host, "google.com");
            assert_eq!(port, 80);
        }

        #[test]
        fn test_parse_http_connect_not_connect() {
            let header = b"GET http://example.com/ HTTP/1.1\r\n\r\n";
            assert!(parse_http_connect_target(header).is_err());
        }

        #[test]
        fn test_parse_http_connect_empty() {
            assert!(parse_http_connect_target(b"").is_err());
        }

        #[test]
        fn test_parse_http_connect_no_port() {
            let header = b"CONNECT example.com HTTP/1.1\r\n\r\n";
            assert!(parse_http_connect_target(header).is_err());
        }

        #[test]
        fn test_parse_http_connect_bad_port() {
            let header = b"CONNECT example.com:abc HTTP/1.1\r\n\r\n";
            assert!(parse_http_connect_target(header).is_err());
        }

        #[test]
        fn test_check_http_basic_auth_valid() {
            let creds = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                "user:pass",
            );
            let header = format!("Proxy-Authorization: Basic {creds}\r\n").into_bytes();
            assert!(check_http_basic_auth(&header, "user", "pass"));
        }

        #[test]
        fn test_check_http_basic_auth_wrong_pass() {
            let creds = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                "user:wrong",
            );
            let header = format!("Proxy-Authorization: Basic {creds}\r\n").into_bytes();
            assert!(!check_http_basic_auth(&header, "user", "pass"));
        }

        #[test]
        fn test_check_http_basic_auth_missing() {
            let header = b"Host: example.com\r\n\r\n";
            assert!(!check_http_basic_auth(header, "user", "pass"));
        }

        #[test]
        fn test_check_http_basic_auth_malformed() {
            let header = b"Proxy-Authorization: Basic !!!not-base64!!!\r\n";
            assert!(!check_http_basic_auth(header, "user", "pass"));
        }

        #[test]
        fn test_check_http_basic_auth_not_basic() {
            let header = b"Proxy-Authorization: Digest abc\r\n";
            assert!(!check_http_basic_auth(header, "user", "pass"));
        }

        #[test]
        fn test_parse_tcp_line_target_host_port() {
            let (host, port) = parse_tcp_line_target(b"example.com:443").unwrap();
            assert_eq!(host, "example.com");
            assert_eq!(port, 443);
        }

        #[test]
        fn test_parse_tcp_line_target_ip_port() {
            let (host, port) = parse_tcp_line_target(b"10.0.0.1:8080").unwrap();
            assert_eq!(host, "10.0.0.1");
            assert_eq!(port, 8080);
        }

        #[test]
        fn test_parse_tcp_line_target_with_newline() {
            let (host, port) = parse_tcp_line_target(b"example.com:443\n").unwrap();
            assert_eq!(host, "example.com");
            assert_eq!(port, 443);
        }

        #[test]
        fn test_parse_tcp_line_target_empty() {
            assert!(parse_tcp_line_target(b"").is_err());
        }

        #[test]
        fn test_parse_tcp_line_target_no_port() {
            assert!(parse_tcp_line_target(b"example.com").is_err());
        }

        #[test]
        fn test_parse_tcp_line_target_empty_host() {
            assert!(parse_tcp_line_target(b":443").is_err());
        }

        #[test]
        fn test_parse_tcp_line_target_bad_port() {
            assert!(parse_tcp_line_target(b"example.com:abc").is_err());
        }

        #[test]
        fn test_parse_tcp_line_target_zero_port() {
            assert!(parse_tcp_line_target(b"example.com:0").is_err());
        }

        #[test]
        fn test_parse_tcp_line_target_space_separated() {
            let (host, port) = parse_tcp_line_target(b"example.com 443").unwrap();
            assert_eq!(host, "example.com");
            assert_eq!(port, 443);
        }

        #[test]
        fn test_pack_and_parse_udp_frame() {
            let packed = pack_udp_frame("test.host", 1234, b"udp data");
            let parsed = read_udp_frame_from_slice(&packed).unwrap();
            assert_eq!(parsed.host, "test.host");
            assert_eq!(parsed.port, 1234);
            assert_eq!(parsed.data, b"udp data");
        }

        #[test]
        fn test_read_udp_frame_bad_version() {
            let mut packed = pack_udp_frame("x", 1, b"d");
            packed[0] = 99;
            assert!(read_udp_frame_from_slice(&packed).is_err());
        }

        #[test]
        fn test_read_udp_frame_too_short() {
            assert!(read_udp_frame_from_slice(&[0, 0]).is_err());
        }

        #[test]
        fn test_read_udp_frame_zero_host_len() {
            let buf = vec![UDP_FRAME_VERSION, 0, 0, 0, 0, 0, 0, 0];
            assert!(read_udp_frame_from_slice(&buf).is_err());
        }

        #[test]
        fn test_socks_udp_parse_short_port() {
            let mut pkt = vec![0x00, 0x00, 0x00, 0x01, 10, 0, 0, 1]; // IPv4 but no port
            assert!(socks_udp_parse_request(&pkt).is_err());
        }

        #[test]
        fn test_socks_udp_parse_bad_rsv() {
            let mut pkt = vec![0x01, 0x00, 0x00, 0x01]; // bad RSV
            pkt.extend_from_slice(&[127, 0, 0, 1]);
            pkt.extend_from_slice(&[0x00, 0x50]);
            assert!(socks_udp_parse_request(&pkt).is_err());
        }
    }
}
