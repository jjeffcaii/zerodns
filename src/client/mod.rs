use async_trait::async_trait;

pub use tcp::{TcpClient, TcpClientBuilder};
pub use udp::{UdpClient, UdpClientBuilder};

use crate::protocol::{Message, DNS};
use crate::Result;

mod tcp;
mod udp;

#[async_trait]
pub trait Client {
    async fn request(&self, req: &Message) -> Result<Message>;
}

pub async fn request(dns: &DNS, request: &Message) -> Result<Message> {
    let ret = match dns {
        DNS::UDP(addr) => {
            let c = UdpClient::builder(*addr).build();
            c.request(request).await
        }
        DNS::TCP(addr) => {
            let c = TcpClient::builder(*addr).build()?;
            c.request(request).await
        }
        _ => todo!(),
    };

    if let Err(e) = &ret {
        error!("request dns failed: {:?}", e);
    }

    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_request() -> anyhow::Result<()> {
        init();

        let dns = DNS::from_str("223.5.5.5")?;
        let req = {
            // type=A domain=baidu.com
            let raw = hex::decode(
                "128e0120000100000000000105626169647503636f6d00000100010000291000000000000000",
            )?;
            Message::from(raw)
        };

        let res = request(&dns, &req).await;

        assert!(res.is_ok_and(|msg| {
            info!("message: {:?}", msg);
            true
        }));

        Ok(())
    }
}
