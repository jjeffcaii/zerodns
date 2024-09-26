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
