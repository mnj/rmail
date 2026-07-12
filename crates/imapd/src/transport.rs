use crate::tls::TlsContext;
use anyhow::{Result, anyhow};
use async_compression::tokio::bufread::ZlibDecoder;
use async_compression::tokio::write::ZlibEncoder;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncWriteExt, BufReader};

pub(crate) trait RawStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized> RawStream for T {}

pub(crate) trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
    fn enable_deflate(&mut self) -> std::io::Result<()>;
    fn compression_active(&self) -> bool;
}

enum SwitchableState {
    Raw(Box<dyn RawStream + Send + 'static>),
    Deflate {
        reader: ZlibDecoder<BufReader<tokio::io::ReadHalf<Box<dyn RawStream + Send + 'static>>>>,
        writer: ZlibEncoder<tokio::io::WriteHalf<Box<dyn RawStream + Send + 'static>>>,
    },
    Transition,
}

pub(crate) struct SwitchableStream {
    state: SwitchableState,
}

impl SwitchableStream {
    pub(crate) fn new(stream: Box<dyn RawStream + Send + 'static>) -> Self {
        Self {
            state: SwitchableState::Raw(stream),
        }
    }
}

impl AsyncStream for SwitchableStream {
    fn enable_deflate(&mut self) -> std::io::Result<()> {
        let state = std::mem::replace(&mut self.state, SwitchableState::Transition);
        match state {
            SwitchableState::Raw(stream) => {
                let (read, write) = tokio::io::split(stream);
                self.state = SwitchableState::Deflate {
                    reader: ZlibDecoder::new(BufReader::new(read)),
                    writer: ZlibEncoder::new(write),
                };
                Ok(())
            }
            other => {
                self.state = other;
                Err(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    "compression already active",
                ))
            }
        }
    }

    fn compression_active(&self) -> bool {
        matches!(self.state, SwitchableState::Deflate { .. })
    }
}

impl tokio::io::AsyncRead for SwitchableStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.state {
            SwitchableState::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            SwitchableState::Deflate { reader, .. } => Pin::new(reader).poll_read(cx, buf),
            SwitchableState::Transition => Poll::Ready(Err(std::io::Error::other(
                "compression transition in progress",
            ))),
        }
    }
}

impl tokio::io::AsyncWrite for SwitchableStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.state {
            SwitchableState::Raw(stream) => Pin::new(stream).poll_write(cx, buf),
            SwitchableState::Deflate { writer, .. } => Pin::new(writer).poll_write(cx, buf),
            SwitchableState::Transition => Poll::Ready(Err(std::io::Error::other(
                "compression transition in progress",
            ))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.state {
            SwitchableState::Raw(stream) => Pin::new(stream).poll_flush(cx),
            SwitchableState::Deflate { writer, .. } => Pin::new(writer).poll_flush(cx),
            SwitchableState::Transition => Poll::Ready(Err(std::io::Error::other(
                "compression transition in progress",
            ))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.state {
            SwitchableState::Raw(stream) => Pin::new(stream).poll_shutdown(cx),
            SwitchableState::Deflate { writer, .. } => Pin::new(writer).poll_shutdown(cx),
            SwitchableState::Transition => Poll::Ready(Err(std::io::Error::other(
                "compression transition in progress",
            ))),
        }
    }
}

pub(crate) async fn enable_deflate(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    mechanism: &str,
) -> Result<()> {
    let compression_active = reader.get_ref().compression_active();
    let has_pipelined_input = !reader.buffer().is_empty();
    let writer = reader.get_mut();
    if !mechanism.eq_ignore_ascii_case("DEFLATE") {
        writer
            .write_all(format!("{tag} NO Unsupported compression mechanism\r\n").as_bytes())
            .await?;
    } else if compression_active {
        writer
            .write_all(
                format!("{tag} NO [COMPRESSIONACTIVE] DEFLATE compression already enabled\r\n")
                    .as_bytes(),
            )
            .await?;
    } else if has_pipelined_input {
        writer
            .write_all(
                format!(
                    "{tag} BAD Client did not wait for COMPRESS reply before sending more data\r\n"
                )
                .as_bytes(),
            )
            .await?;
    } else {
        writer
            .write_all(format!("{tag} OK Begin compression\r\n").as_bytes())
            .await?;
        writer.flush().await?;
        writer.enable_deflate()?;
        return Ok(());
    }
    writer.flush().await?;
    Ok(())
}

pub(crate) enum StartTlsOutcome {
    Rejected(BufReader<Box<dyn AsyncStream + Send + 'static>>),
    Upgraded(Box<dyn RawStream + Send + 'static>),
}

pub(crate) async fn start_tls(
    mut reader: BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    tls_context: Option<Arc<TlsContext>>,
) -> Result<StartTlsOutcome> {
    let Some(tls_context) = tls_context else {
        reader
            .get_mut()
            .write_all(format!("{tag} NO TLS not available\r\n").as_bytes())
            .await?;
        reader.get_mut().flush().await?;
        return Ok(StartTlsOutcome::Rejected(reader));
    };
    if !reader.buffer().is_empty() {
        reader
            .get_mut()
            .write_all(
                format!(
                    "{tag} BAD Client did not wait for STARTTLS reply before sending more data\r\n"
                )
                .as_bytes(),
            )
            .await?;
        reader.get_mut().flush().await?;
        return Ok(StartTlsOutcome::Rejected(reader));
    }

    reader
        .get_mut()
        .write_all(format!("{tag} OK Begin TLS negotiation now\r\n").as_bytes())
        .await?;
    reader.get_mut().flush().await?;
    let stream = tls_context
        .acceptor
        .accept(reader.into_inner())
        .await
        .map_err(|error| anyhow!("TLS accept failed: {error}"))?;
    Ok(StartTlsOutcome::Upgraded(Box::new(stream)))
}
