use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use super::frame::Message;

#[derive(Default, Debug, Copy, Clone)]
pub struct Codec;

impl Encoder<&Message> for Codec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: &Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_u16(item.len() as u16);
        dst.extend_from_slice(&item.0[..]);
        Ok(())
    }
}

impl Decoder for Codec {
    type Item = Message;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let total = src.len();
        if total < 2 {
            return Ok(None);
        }
        let size = BigEndian::read_u16(&src[..]) as usize;
        if total < size + 2 {
            return Ok(None);
        }

        let _ = src.split_to(2);
        let b = src.split_to(size);

        Ok(Some(Message::from(b)))
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use futures::{SinkExt, StreamExt};
    use tokio_util::codec::{FramedRead, FramedWrite};

    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_encode_and_decode() {
        init();

        let b = Vec::<u8>::new();
        let mut w = FramedWrite::new(b, Codec);

        let msg = {
            let b = hex::decode("ef968180000100020000000105626169647503636f6d0000010001c00c00010001000001d400046ef24442c00c00010001000001d40004279c420a0000290580000000000000").unwrap();
            Message::from(b)
        };

        let res = w.send(&msg).await;
        assert!(res.is_ok());

        let raw = w.into_inner();
        let b = BytesMut::from(&raw[..]);

        let mut read = FramedRead::new(&b[..], Codec);
        let first = read.next().await;

        assert!(first.is_some_and(|v| v.is_ok_and(|msg| {
            assert_eq!(70, msg.len());
            assert_eq!(0xef96, msg.id());

            info!("id: 0x{:x}", msg.id());
            for (i, question) in msg.questions().enumerate() {
                info!("question#{}: name={}", i, question.name_string());
            }
            for (i, answer) in msg.answers().enumerate() {
                let data = answer.data();
                assert_eq!(4, data.len());
                let ip = std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                info!("answer#{}: name={} addr={:?}", i, answer.name_string(), ip);
            }

            true
        })));
    }
}
