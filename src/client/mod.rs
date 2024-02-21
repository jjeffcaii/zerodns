mod tcp;
mod udp;

use async_trait::async_trait;

use crate::protocol::Message;
use crate::Result;

#[async_trait]
pub trait Client {
    async fn request(&self, req: &Message) -> Result<Option<Message>>;
}

pub use tcp::{TcpClient, TcpClientBuilder};
pub use udp::{UdpClient, UdpClientBuilder};
