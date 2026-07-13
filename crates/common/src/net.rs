use anyhow::{Context, Result};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TcpListenerConfig {
    #[serde(default = "default_backlog")]
    pub backlog: u32,
    /// Permit multiple rMail processes to bind the same address for rolling
    /// restarts or kernel-level load distribution. Disabled by default.
    #[serde(default)]
    pub reuse_port: bool,
    /// Keep IPv6 wildcard listeners separate from IPv4 listeners. Set false to
    /// make a single `[::]:port` listener accept both address families.
    #[serde(default = "default_ipv6_only")]
    pub ipv6_only: bool,
}

const fn default_backlog() -> u32 {
    1024
}

const fn default_ipv6_only() -> bool {
    true
}

impl Default for TcpListenerConfig {
    fn default() -> Self {
        Self {
            backlog: default_backlog(),
            reuse_port: false,
            ipv6_only: default_ipv6_only(),
        }
    }
}

pub fn bind_tcp_listener(addr: &str) -> Result<TcpListener> {
    bind_tcp_listener_with_config(addr, &TcpListenerConfig::default())
}

pub fn bind_tcp_listener_with_config(
    addr: &str,
    config: &TcpListenerConfig,
) -> Result<TcpListener> {
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid listen address {addr:?}"))?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .with_context(|| format!("creating socket for {addr}"))?;
    socket
        .set_reuse_address(true)
        .with_context(|| format!("setting SO_REUSEADDR for {addr}"))?;
    if config.reuse_port {
        #[cfg(unix)]
        socket
            .set_reuse_port(true)
            .with_context(|| format!("setting SO_REUSEPORT for {addr}"))?;
        #[cfg(not(unix))]
        anyhow::bail!("reuse_port is not supported on this platform");
    }
    if addr.is_ipv6() {
        socket
            .set_only_v6(config.ipv6_only)
            .with_context(|| format!("setting IPV6_V6ONLY for {addr}"))?;
    }
    socket
        .set_nonblocking(true)
        .with_context(|| format!("setting nonblocking mode for {addr}"))?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("binding listener on {addr}"))?;
    let backlog =
        i32::try_from(config.backlog).context("TCP listener backlog exceeds the platform limit")?;
    if backlog < 1 {
        anyhow::bail!("TCP listener backlog must be at least 1");
    }
    socket
        .listen(backlog)
        .with_context(|| format!("listening on {addr}"))?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener).with_context(|| format!("creating tokio listener for {addr}"))
}

#[cfg(test)]
mod tests {
    use super::{TcpListenerConfig, bind_tcp_listener, bind_tcp_listener_with_config};

    #[tokio::test]
    async fn ipv4_and_ipv6_loopback_can_share_port() {
        let v4 = bind_tcp_listener("127.0.0.1:0").expect("bind ipv4");
        let port = v4.local_addr().expect("local addr").port();
        let v6_addr = format!("[::1]:{port}");

        match bind_tcp_listener(&v6_addr) {
            Ok(_v6) => {}
            Err(err) => {
                let text = err.to_string();
                if text.contains("Cannot assign requested address")
                    || text.contains("Address family not supported")
                    || text.contains("Network is unreachable")
                {
                    return;
                }
                panic!("failed to bind IPv6 loopback on same port: {err:#}");
            }
        }
    }

    #[tokio::test]
    async fn listener_can_rebind_immediately_after_active_connection_closes() {
        let listener = bind_tcp_listener("127.0.0.1:0").expect("first bind");
        let address = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop(listener);
        drop(server);
        drop(client);

        bind_tcp_listener(&address.to_string()).expect("immediate rebind with SO_REUSEADDR");
    }

    #[tokio::test]
    async fn ipv6_wildcard_can_be_configured_as_one_dual_stack_socket() {
        let config = TcpListenerConfig {
            ipv6_only: false,
            ..TcpListenerConfig::default()
        };
        let listener = match bind_tcp_listener_with_config("[::]:0", &config) {
            Ok(listener) => listener,
            Err(error)
                if error.to_string().contains("Address family not supported")
                    || error
                        .to_string()
                        .contains("Cannot assign requested address") =>
            {
                return;
            }
            Err(error) => panic!("dual-stack bind failed: {error:#}"),
        };
        let port = listener.local_addr().unwrap().port();
        let client = tokio::net::TcpStream::connect(("127.0.0.1", port));
        let accepted = listener.accept();
        let (client, accepted) = tokio::join!(client, accepted);

        client.expect("IPv4 connection to dual-stack listener");
        accepted.expect("accept IPv4 connection on IPv6 wildcard");
    }

    #[test]
    fn listener_options_validate_backlog() {
        let config = TcpListenerConfig {
            backlog: 0,
            ..TcpListenerConfig::default()
        };
        assert!(bind_tcp_listener_with_config("127.0.0.1:0", &config).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reuse_port_is_explicit_and_allows_parallel_listeners() {
        let config = TcpListenerConfig {
            reuse_port: true,
            ..TcpListenerConfig::default()
        };
        let first = bind_tcp_listener_with_config("127.0.0.1:0", &config).unwrap();
        let address = first.local_addr().unwrap();
        let second = bind_tcp_listener_with_config(&address.to_string(), &config).unwrap();

        assert_eq!(second.local_addr().unwrap(), address);
    }
}
