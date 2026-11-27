//! Process-wide relay dial filter.
//!
//! Pinned MDK sends every nostr-sdk relay connection through `WN_SOCKS5_PROXY`
//! when that variable is set, and it does not fall back to a direct dial.
//! The hostname is handed to the proxy. This process resolves it, refuses
//! private, loopback, link-local, and metadata destinations, and connects to
//! an address that passed that check. A later DNS answer cannot move the
//! TCP connection. `--allow-loopback` allows loopback only, and only for the
//! fixture. It does not allow RFC1918, link-local, or metadata addresses.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use watchdog_core::url_policy::is_blocked_address;

static INSTALLED: Mutex<Option<SocketAddr>> = Mutex::new(None);

pub fn install_egress(allow_loopback: bool) -> Result<(), String> {
    let mut installed = INSTALLED.lock().map_err(|_| "egress_lock".to_string())?;
    if installed.is_some() {
        return Ok(());
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("egress_bind: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("egress_bind: {error}"))?;
    let addr = listener
        .local_addr()
        .map_err(|error| format!("egress_bind: {error}"))?;
    std::thread::Builder::new()
        .name("marmot-egress".to_string())
        .spawn(move || serve_forever(listener, allow_loopback))
        .map_err(|error| format!("egress_thread: {error}"))?;
    // MDK reads this once, on the first relay client. The helper binary calls
    // install_egress before it starts a runtime. Clearing credentials keeps
    // MDK on the unauthenticated SOCKS5 path this filter implements.
    unsafe {
        std::env::set_var("WN_SOCKS5_PROXY", addr.to_string());
        std::env::remove_var("WN_SOCKS5_USERNAME");
        std::env::remove_var("WN_SOCKS5_PASSWORD");
    }
    *installed = Some(addr);
    Ok(())
}

fn serve_forever(listener: std::net::TcpListener, allow_loopback: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("egress runtime");
    runtime.block_on(async move {
        let listener = match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(_) => return,
        };
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        let _ = handle(stream, allow_loopback).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    });
}

async fn handle(mut client: TcpStream, allow_loopback: bool) -> io::Result<()> {
    let handshake = async {
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await?;
        if header[0] != 5 {
            return Err(io::Error::new(ErrorKind::InvalidData, "socks version"));
        }
        let mut methods = vec![0u8; header[1] as usize];
        if !methods.is_empty() {
            client.read_exact(&mut methods).await?;
        }
        if !methods.contains(&0) {
            client.write_all(&[5, 0xff]).await?;
            return Err(io::Error::new(ErrorKind::PermissionDenied, "socks auth"));
        }
        client.write_all(&[5, 0]).await?;
        let mut request = [0u8; 4];
        client.read_exact(&mut request).await?;
        if request[0] != 5 || request[1] != 1 {
            reject(&mut client, 7).await?;
            return Err(io::Error::new(ErrorKind::InvalidData, "socks command"));
        }
        let target = match read_target(&mut client, request[3]).await {
            Ok(target) => target,
            Err(_) => {
                reject(&mut client, 8).await?;
                return Err(io::Error::new(ErrorKind::InvalidData, "socks address"));
            }
        };
        let addresses = match resolve_target(&target, allow_loopback).await {
            Ok(addresses) => addresses,
            Err(code) => {
                reject(&mut client, code).await?;
                return Err(io::Error::new(ErrorKind::PermissionDenied, "socks policy"));
            }
        };
        let mut upstream = None;
        for address in addresses.into_iter().take(4) {
            if let Ok(stream) =
                tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(address)).await
            {
                if let Ok(stream) = stream {
                    upstream = Some(stream);
                    break;
                }
            }
        }
        let Some(mut upstream) = upstream else {
            reject(&mut client, 5).await?;
            return Err(io::Error::new(
                ErrorKind::ConnectionRefused,
                "socks connect",
            ));
        };
        client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        Ok(())
    };
    match tokio::time::timeout(Duration::from_secs(20), handshake).await {
        Ok(result) => result,
        Err(_) => Ok(()),
    }
}

async fn reject(client: &mut TcpStream, code: u8) -> io::Result<()> {
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

async fn read_target(client: &mut TcpStream, kind: u8) -> io::Result<Target> {
    match kind {
        1 => {
            let mut bytes = [0u8; 6];
            client.read_exact(&mut bytes).await?;
            let port = u16::from_be_bytes([bytes[4], bytes[5]]);
            Ok(Target::Ip(
                IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]),
                port,
            ))
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            if name.is_empty() {
                return Err(io::Error::new(ErrorKind::InvalidData, "empty host"));
            }
            client.read_exact(&mut name).await?;
            let host = String::from_utf8(name)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "host"))?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            Ok(Target::Name(host, u16::from_be_bytes(port)))
        }
        4 => {
            let mut bytes = [0u8; 18];
            client.read_exact(&mut bytes).await?;
            let mut address = [0u8; 16];
            address.copy_from_slice(&bytes[..16]);
            let port = u16::from_be_bytes([bytes[16], bytes[17]]);
            Ok(Target::Ip(IpAddr::from(address), port))
        }
        _ => Err(io::Error::new(ErrorKind::InvalidData, "address type")),
    }
}

enum Target {
    Ip(IpAddr, u16),
    Name(String, u16),
}

async fn resolve_target(target: &Target, allow_loopback: bool) -> Result<Vec<SocketAddr>, u8> {
    match target {
        Target::Ip(address, port) => {
            if !address_allowed(*address, allow_loopback) {
                return Err(2);
            }
            Ok(vec![SocketAddr::new(*address, *port)])
        }
        Target::Name(host, port) => {
            if prohibited_name(host, allow_loopback) {
                return Err(2);
            }
            if let Ok(address) = host.parse::<IpAddr>() {
                if !address_allowed(address, allow_loopback) {
                    return Err(2);
                }
                return Ok(vec![SocketAddr::new(address, *port)]);
            }
            let looked = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), *port)),
            )
            .await
            .map_err(|_| 4u8)?
            .map_err(|_| 4u8)?;
            let addresses: Vec<IpAddr> = looked.map(|address| address.ip()).collect();
            if addresses.is_empty() || !destinations_allowed(host, &addresses, allow_loopback) {
                return Err(2);
            }
            Ok(addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, *port))
                .collect())
        }
    }
}

pub(crate) fn destinations_allowed(host: &str, addresses: &[IpAddr], allow_loopback: bool) -> bool {
    !prohibited_name(host, allow_loopback)
        && !addresses.is_empty()
        && addresses
            .iter()
            .all(|address| address_allowed(*address, allow_loopback))
}

fn address_allowed(address: IpAddr, allow_loopback: bool) -> bool {
    if allow_loopback && address.is_loopback() {
        return true;
    }
    !is_blocked_address(&address.to_string())
}

fn prohibited_name(host: &str, allow_loopback: bool) -> bool {
    let host = host
        .trim_matches(|ch| ch == '.' || ch == '[' || ch == ']')
        .to_ascii_lowercase();
    if host.is_empty() || host.parse::<IpAddr>().is_ok() {
        return host.is_empty();
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return !allow_loopback;
    }
    host == "metadata"
        || host == "metadata.google.internal"
        || host.ends_with(".metadata.google.internal")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_and_prohibited_answers_are_refused() {
        let public = "1.1.1.1".parse().unwrap();
        let private = "10.1.2.3".parse().unwrap();
        let loopback = "127.0.0.1".parse().unwrap();
        let link_local = "169.254.169.254".parse().unwrap();
        let metadata_v6 = "fe80::1".parse().unwrap();
        assert!(destinations_allowed("relay.example", &[public], false));
        assert!(!destinations_allowed(
            "relay.example",
            &[public, private],
            false
        ));
        assert!(!destinations_allowed("relay.example", &[private], true));
        assert!(!destinations_allowed("relay.example", &[loopback], false));
        assert!(destinations_allowed("relay.example", &[loopback], true));
        assert!(!destinations_allowed("relay.example", &[link_local], true));
        assert!(!destinations_allowed("relay.example", &[metadata_v6], true));
        assert!(!destinations_allowed(
            "metadata.google.internal",
            &[public],
            true
        ));
        assert!(!destinations_allowed("metadata.internal", &[public], false));
        assert!(!destinations_allowed("cache.local", &[public], false));
        assert!(!destinations_allowed("host.home.arpa", &[public], false));
        assert!(!destinations_allowed("localhost", &[loopback], false));
        assert!(destinations_allowed("localhost", &[loopback], true));
    }

    #[tokio::test]
    async fn the_filter_connects_to_loopback_only_when_the_fixture_flag_is_set() {
        let allowed = spawn_test_proxy(true).await;
        let blocked = spawn_test_proxy(false).await;
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });
        let mut allowed_stream = connect_ready(allowed).await;
        socks_connect(
            &mut allowed_stream,
            &echo_addr.ip().to_string(),
            echo_addr.port(),
        )
        .await
        .unwrap();
        allowed_stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        allowed_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        let mut blocked_stream = connect_ready(blocked).await;
        let refusal = socks_connect(&mut blocked_stream, "127.0.0.1", echo_addr.port())
            .await
            .unwrap_err();
        assert_eq!(refusal, 2);
        let mut private_stream = connect_ready(blocked).await;
        let private = socks_connect(&mut private_stream, "10.1.2.3", 9)
            .await
            .unwrap_err();
        assert_eq!(private, 2);
        let mut metadata_stream = connect_ready(blocked).await;
        let metadata = socks_connect(&mut metadata_stream, "metadata.google.internal", 80)
            .await
            .unwrap_err();
        assert_eq!(metadata, 2);
        let mut link_stream = connect_ready(blocked).await;
        let link = socks_connect(&mut link_stream, "169.254.169.254", 80)
            .await
            .unwrap_err();
        assert_eq!(link, 2);
    }

    async fn connect_ready(addr: SocketAddr) -> TcpStream {
        for _ in 0..50 {
            if let Ok(stream) = TcpStream::connect(addr).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("proxy did not accept");
    }

    async fn spawn_test_proxy(allow_loopback: bool) -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || serve_forever(listener, allow_loopback));
        tokio::time::sleep(Duration::from_millis(50)).await;
        addr
    }

    async fn socks_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), u8> {
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        if reply[1] == 0 {
            Ok(())
        } else {
            Err(reply[1])
        }
    }
}
