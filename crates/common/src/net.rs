use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub fn bind_tcp_listener(addr: &str) -> Result<TcpListener> {
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
    if addr.is_ipv6() {
        socket
            .set_only_v6(true)
            .with_context(|| format!("setting IPV6_V6ONLY for {addr}"))?;
    }
    socket
        .set_nonblocking(true)
        .with_context(|| format!("setting nonblocking mode for {addr}"))?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("binding listener on {addr}"))?;
    socket
        .listen(1024)
        .with_context(|| format!("listening on {addr}"))?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener).with_context(|| format!("creating tokio listener for {addr}"))
}

#[cfg(test)]
mod tests {
    use super::bind_tcp_listener;

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
}
