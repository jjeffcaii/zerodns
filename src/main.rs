#[macro_use]
extern crate log;

use bytes::Bytes;
use tokio::net::UdpSocket;

use crate::protocol::Message;
use crate::server::{Handler, Server};

pub mod protocol;
pub mod server;

pub type Result<T> = anyhow::Result<T>;

struct MockHandler;

#[async_trait::async_trait]
impl Handler for MockHandler {
    async fn handle(&self, req: &Message) -> Result<Message> {
        info!("------------------------------------------------");
        info!("id: {}", req.id());
        info!("response: {}", req.flags().is_response());
        let q = req.queries();

        let mut w = smallvec::SmallVec::<[u8; 64]>::new();
        for (i, next) in q.name().enumerate() {
            if i != 0 {
                w.push(b'.');
            }
            w.extend_from_slice(next);
        }
        info!("name: {}", String::from_utf8_lossy(&w[..]));
        info!("type: {:?}", q.typ());
        info!("class: {:?}", q.class());

        info!("------------------------------------------------");

        let mut resp = hex::decode("f2728180000100020000000105626169647503636f6d0000010001c00c000100010000019e0004279c420ac00c000100010000019e00046ef244420000290580000000000000")?;

        use byteorder::{BigEndian, ByteOrder};

        BigEndian::write_u16(&mut resp, req.id());

        Ok(Message::from(Bytes::from(resp)))
    }
}

fn init() {
    pretty_env_logger::try_init_timed().ok();
}

#[tokio::main]
async fn main() -> Result<()> {
    init();

    let socket = UdpSocket::bind("127.0.0.1:5757").await?;

    let server = Server::new(socket, MockHandler);

    server.run().await?;

    // RUN:
    // dig +short @127.0.0.1 -p5757 baidu.com

    Ok(())
}
