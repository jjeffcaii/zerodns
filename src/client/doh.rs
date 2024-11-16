use super::Client;
use crate::misc::http::{SimpleHttp1Codec, CRLF};
use crate::protocol::Message;
use futures::StreamExt;
use once_cell::sync::Lazy;
use smallvec::{smallvec, SmallVec};
use std::fmt::{Display, Formatter};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::codec::FramedRead;

use crate::Error::NetworkFailure;

static CLOUDFLARE: Lazy<DoHClient> =
    Lazy::new(|| DoHClient::builder("1.1.1.1:443".parse().unwrap()).build());

static ALIYUN: Lazy<DoHClient> = Lazy::new(|| {
    DoHClient::builder("223.5.5.5:443".parse().unwrap())
        .host("dns.alidns.com")
        .build()
});

static GOOGLE: Lazy<DoHClient> = Lazy::new(|| {
    DoHClient::builder("8.8.8.8:443".parse().unwrap())
        .host("dns.google")
        .build()
});

pub struct DoHClientBuilder<'a> {
    https: bool,
    addr: SocketAddr,
    host: Option<&'a str>,
    path: Option<&'a str>,
    timeout: Duration,
}

impl<'a> DoHClientBuilder<'a> {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn host(mut self, host: &'a str) -> Self {
        self.host = Some(host);
        self
    }

    pub fn https(mut self, https: bool) -> Self {
        self.https = https;
        self
    }

    pub fn path(mut self, path: &'a str) -> Self {
        self.path = Some(path);
        self
    }

    pub fn build(self) -> DoHClient {
        let Self {
            https,
            addr,
            host,
            path,
            timeout,
        } = self;
        let host = host
            .map(|it| it.to_string())
            .unwrap_or_else(|| addr.ip().to_string());

        DoHClient {
            https,
            addr,
            host: Arc::new(host),
            path: path.map(|it| Arc::new(it.to_string())),
            timeout,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DoHClient {
    https: bool,
    addr: SocketAddr,
    host: Arc<String>,
    path: Option<Arc<String>>,
    timeout: Duration,
}

impl DoHClient {
    pub const DEFAULT_PATH: &'static str = "/dns-query";

    pub fn builder<'a>(addr: SocketAddr) -> DoHClientBuilder<'a> {
        let https = addr.port() == 443;
        DoHClientBuilder {
            https,
            addr,
            host: None,
            path: None,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn google() -> Self {
        Clone::clone(&*GOOGLE)
    }

    pub fn cloudflare() -> Self {
        Clone::clone(&*CLOUDFLARE)
    }

    pub fn aliyun() -> Self {
        Clone::clone(&*ALIYUN)
    }

    #[inline]
    async fn request_timeout<S>(&self, stream: &mut S, req: &Message) -> crate::Result<Message>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        tokio::time::timeout(self.timeout, self.request_(stream, req)).await?
    }

    #[inline]
    async fn request_<S>(&self, stream: &mut S, req: &Message) -> crate::Result<Message>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (r, mut w) = tokio::io::split(stream);

        // https://www.rfc-editor.org/rfc/rfc8484.html#section-6
        // https://www.rfc-editor.org/rfc/rfc4648#section-5
        let b64req = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            URL_SAFE_NO_PAD.encode(req)
        };

        {
            let mut buf: SmallVec<[u8; 1024]> = smallvec![];
            match &self.path {
                Some(path) => write!(&mut buf, "GET {}?dns={} HTTP/1.1{}", path, b64req, CRLF)?,
                None => write!(
                    &mut buf,
                    "GET {}?dns={} HTTP/1.1{}",
                    Self::DEFAULT_PATH,
                    b64req,
                    CRLF
                )?,
            }

            write!(&mut buf, "Host: {}{}", &self.host, CRLF)?;
            write!(&mut buf, "User-Agent: zerodns/0.1.0{}", CRLF)?;
            write!(&mut buf, "Accept: application/dns-message{}", CRLF)?;
            write!(&mut buf, "{}", CRLF)?;

            w.write_all(&buf[..]).await?;
            w.flush().await?;
        }

        let mut reader = FramedRead::new(r, SimpleHttp1Codec::default());

        let res = reader
            .next()
            .await
            .ok_or_else(|| crate::Error::ResolveNothing)??;

        // TODO: handle HTTP/1.1 keepalive

        info!("receive DoH response: {:?}", &res);

        if !res.status().is_success() {
            bail!(NetworkFailure(io::Error::new(
                io::ErrorKind::Other,
                "unexpected HTTP status"
            )));
        }

        let msg = Message::from(res.into_body());
        Ok(msg)
    }
}

impl Display for DoHClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.https {
            if self.addr.port() == 443 {
                write!(f, "doh+https://{}", self.addr.ip())?;
            } else {
                write!(f, "doh+https://{}", self.addr)?;
            }
        } else if self.addr.port() == 80 {
            write!(f, "doh+http://{}", self.addr.ip())?;
        } else {
            write!(f, "doh+http://{}", self.addr)?;
        }
        match &self.path {
            None => write!(f, "{}", Self::DEFAULT_PATH)?,
            Some(path) => write!(f, "{}", path.as_str())?,
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Client for DoHClient {
    async fn request(&self, req: &Message) -> crate::Result<Message> {
        if self.https {
            let key = (Clone::clone(&self.host), Clone::clone(&self.addr));
            let pool = crate::misc::tls::get(key)?;

            let mut obj = pool
                .get()
                .await
                .map_err(|e| anyhow!("cannot get tcp stream: {:?}", e))?;

            self.request_timeout(&mut obj.1, req).await
        } else {
            let mut stream = TcpStream::connect(self.addr).await?;
            self.request_timeout(&mut stream, req).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Class, Flags, Kind, Message};

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_doh_client() -> anyhow::Result<()> {
        init();

        for c in [
            DoHClient::aliyun(),
            DoHClient::cloudflare(),
            DoHClient::google(),
        ] {
            for question in ["www.youtube.com", "www.taobao.com", "x.com"] {
                info!("-------- resolve {} from {} --------", question, &c);

                let req = Message::builder()
                    .id(0x1234)
                    .flags(Flags::builder().request().recursive_query(true).build())
                    .question(question, Kind::A, Class::IN)
                    .build()?;
                let res = c.request(&req).await;

                if let Err(e) = &res {
                    error!("cannot request: {}", e);
                }

                assert!(res.is_ok_and(|msg| {
                    for next in msg.answers() {
                        info!(
                            "{}.\t{}\t{:?}\t{:?}\t{}",
                            next.name(),
                            next.time_to_live(),
                            next.class(),
                            next.kind(),
                            next.rdata().unwrap()
                        );
                    }
                    msg.answer_count() > 0
                }));
            }
        }

        Ok(())
    }
}
