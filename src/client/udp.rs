use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use tokio::net::UdpSocket;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

use crate::protocol::Message;
use crate::Result;

use super::Client;

#[derive(Debug, Clone)]
pub struct UdpClient {
    addr: SocketAddr,
    timeout: Option<Duration>,
}

impl UdpClient {
    pub fn builder(addr: SocketAddr) -> UdpClientBuilder {
        UdpClientBuilder {
            inner: Self {
                addr,
                timeout: None,
            },
        }
    }
}

#[async_trait]
impl Client for UdpClient {
    async fn request(&self, req: &Message) -> Result<Option<Message>> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;

        let mut framed = UdpFramed::new(socket, BytesCodec::default());

        framed.send((req.clone().0.freeze(), self.addr)).await?;

        match framed.next().await {
            Some(next) => {
                let (b, _) = next?;
                Ok(Some(Message::from(b)))
            }
            None => Ok(None),
        }
    }
}

pub struct UdpClientBuilder {
    inner: UdpClient,
}

impl UdpClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner.timeout.replace(timeout);
        self
    }

    pub fn build(self) -> UdpClient {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::client::Client;
    use crate::protocol::{Class, Flags, Kind, Message, OpCode};

    use super::UdpClient;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_request() -> anyhow::Result<()> {
        init();

        let c = UdpClient::builder("223.5.5.5:53".parse()?)
            .timeout(Duration::from_secs(3))
            .build();

        let req = Message::builder()
            .id(0x1234)
            .flags(
                Flags::builder()
                    .request()
                    .opcode(OpCode::StandardQuery)
                    .recursive_query(true)
                    .build(),
            )
            .question("baidu.com", Kind::A, Class::IN)
            .build()?;

        let res = c.request(&req).await?;

        assert!(res.is_some_and(|msg| {
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

        Ok(())
    }
}
