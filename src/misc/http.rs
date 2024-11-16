use crate::error::Error::NetworkFailure;
use bytes::{Buf, Bytes, BytesMut};
use http::Response;
use smallvec::{smallvec, SmallVec};
use std::io;
use tokio_util::codec::Decoder;

pub(crate) const CRLF: &str = "\r\n";

#[derive(Default)]
pub(crate) struct SimpleHttp1Codec {}

impl Decoder for SimpleHttp1Codec {
    type Item = Response<Bytes>;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut headers: SmallVec<[_; 16]> = smallvec![];
        let (code, version, amt) = {
            let mut parsed_headers = [httparse::EMPTY_HEADER; 64];
            let mut res = httparse::Response::new(&mut parsed_headers);

            let status = res.parse(src)?;
            let amt = match status {
                httparse::Status::Complete(amt) => amt,
                httparse::Status::Partial => return Ok(None),
            };

            let locate = |a: &[u8]| {
                let start = a.as_ptr() as usize - src.as_ptr() as usize;
                assert!(start < src.len());
                (start, start + a.len())
            };

            for (i, header) in res.headers.iter().enumerate() {
                let k = locate(header.name.as_bytes());
                let v = locate(header.value);
                headers.push((k, v));
            }

            (res.code.unwrap(), res.version.unwrap(), amt)
        };

        if version != 1 {
            bail!(NetworkFailure(io::Error::new(
                io::ErrorKind::Other,
                "only HTTP/1.1 accepted"
            )));
        }

        let mut content_length = 0usize;
        let mut bu = Response::builder()
            .status(code)
            .version(http::Version::HTTP_11);
        for (k, v) in headers.iter() {
            let header_name = &src[k.0..k.1];
            let header_value = http::HeaderValue::from_bytes(&src[v.0..v.1]).map_err(|_| {
                NetworkFailure(io::Error::new(io::ErrorKind::Other, "header decode error"))
            })?;
            if header_name.eq_ignore_ascii_case(b"Content-Length") {
                content_length = header_value.to_str()?.parse::<usize>()?;
            }
            bu = bu.header(header_name, header_value);
        }

        // TODO: chunked
        // TODO: content-encoding

        Ok(if content_length < 1 {
            Some(bu.body(Bytes::new())?)
        } else if src.remaining() < amt + content_length {
            None
        } else {
            src.advance(amt);
            let body = src.split_to(content_length).freeze();
            Some(bu.body(body)?)
        })
    }
}
