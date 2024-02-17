use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Kind {
    /// a host address
    A = 1,
    /// an authoritative name handler
    NS = 2,
    /// a mail destination
    MD = 3,
    /// a mail forwarder
    MF = 4,
    /// the canonical name for an alias
    CNAME = 5,
    /// a marks the start of a zone of authority
    SOA = 6,
    /// a mailbox domain name
    MB = 7,
    /// a mail group member
    MG = 8,
    /// a mail rename domain name
    MR = 9,
    /// a null RR
    NULL = 10,
    /// a well known service description
    WKS = 11,
    /// a domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,

    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
    /// service and protocol
    SRV = 33,

    AAAA = 28,

    IXFR = 251,

    /// A request for a transfer of an entire zone
    AXFR = 252,
    /// A request for mailbox-related records (MB, MG or MR)
    MAILB = 253,
    /// A request for mail agent RRs
    MAILA = 254,
    /// A request for all records
    ANY = 255,
}

impl Kind {
    pub fn parse_u16(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::A),
            2 => Some(Self::NS),
            3 => Some(Self::MD),
            4 => Some(Self::MF),
            5 => Some(Self::CNAME),
            6 => Some(Self::SOA),
            7 => Some(Self::MB),
            8 => Some(Self::MG),
            9 => Some(Self::MR),
            10 => Some(Self::NULL),
            11 => Some(Self::WKS),
            12 => Some(Self::PTR),
            13 => Some(Self::HINFO),
            14 => Some(Self::MINFO),
            15 => Some(Self::MX),
            16 => Some(Self::TXT),
            33 => Some(Self::SRV),
            28 => Some(Self::AAAA),
            251 => Some(Self::IXFR),
            252 => Some(Self::AXFR),
            253 => Some(Self::MAILB),
            254 => Some(Self::MAILA),
            255 => Some(Self::ANY),
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum QClass {
    /// the Internet
    IN = 1,
    /// the CSNET
    CS = 2,
    /// the CHAOS, see https://en.wikipedia.org/wiki/Chaosnet
    CH = 3,
    /// Hesiod, see https://en.wikipedia.org/wiki/Hesiod_(name_service)
    HS = 4,
}

impl QClass {
    pub fn parse_u16(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::IN),
            2 => Some(Self::CS),
            3 => Some(Self::CH),
            4 => Some(Self::HS),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpCode {
    StandardQuery = 0,
    InverseQuery = 1,
    Status = 2,
    Reserved = 3,
    Notify = 4,
    Update = 5,
}

/// DNS Message Flags:
///  - http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flags(u16);

impl Flags {
    pub fn is_response(&self) -> bool {
        self.0 & 0x8000 != 0
    }

    pub fn opcode(&self) -> OpCode {
        match (self.0 >> 11) & 0x000f {
            0 => OpCode::StandardQuery,
            1 => OpCode::InverseQuery,
            2 => OpCode::Status,
            3 => OpCode::Reserved,
            4 => OpCode::Notify,
            5 => OpCode::Update,
            _ => unreachable!(),
        }
    }

    pub fn is_authoritative(&self) -> bool {
        (self.0 >> 10) & 0x01 != 0
    }

    pub fn is_message_truncated(&self) -> bool {
        (self.0 >> 9) & 0x01 != 0
    }

    pub fn is_recursive_query(&self) -> bool {
        (self.0 >> 8) & 0x01 != 0
    }

    pub fn is_recursion_available(&self) -> bool {
        (self.0 >> 7) & 0x01 != 0
    }

    pub fn reserved(&self) -> u16 {
        // 3 bits
        (self.0 >> 4) & 0x0007
    }

    pub fn response_code(&self) -> RCode {
        match self.0 & 0x000f {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            3 => RCode::NameError,
            4 => RCode::NotImplemented,
            5 => RCode::Refused,
            6 => RCode::YXDomain,
            7 => RCode::YXRRSet,
            8 => RCode::NXRRSet,
            9 => RCode::NotAuth,
            10 => RCode::NotZone,
            _ => unreachable!(),
        }
    }
}

/// DNS message, see links below:
///  - https://www.firewall.cx/networking/network-protocols/dns-protocol/protocols-dns-query.html
///  - http://www.tcpipguide.com/free/t_DNSMessagingandMessageResourceRecordandMasterFileF.htm
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Message(pub(crate) BytesMut);

impl Message {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn id(&self) -> u16 {
        BigEndian::read_u16(&self.0[..])
    }

    pub fn set_id(&mut self, id: u16) {
        BigEndian::write_u16(&mut self.0[..], id);
    }

    pub fn flags(&self) -> Flags {
        Flags(BigEndian::read_u16(&self.0[2..]))
    }

    #[inline]
    pub fn question_count(&self) -> u16 {
        BigEndian::read_u16(&self.0[4..])
    }

    pub fn questions(&self) -> impl Iterator<Item = Question<'_>> {
        QuestionIter {
            raw: &self.0,
            offset: 12,
            lefts: self.question_count(),
        }
    }

    #[inline]
    pub fn answer_count(&self) -> u16 {
        BigEndian::read_u16(&self.0[6..])
    }

    pub fn answers(&self) -> impl Iterator<Item = RR<'_>> {
        let mut offset = 12;
        for next in self.questions() {
            offset += next.len();
        }

        RRIter {
            raw: &self.0[..],
            offset,
            lefts: self.answer_count(),
        }
    }

    pub fn authority_count(&self) -> u16 {
        BigEndian::read_u16(&self.0[8..])
    }

    pub fn additional_count(&self) -> u16 {
        BigEndian::read_u16(&self.0[10..])
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl From<BytesMut> for Message {
    fn from(value: BytesMut) -> Self {
        Self(value)
    }
}

impl From<Bytes> for Message {
    fn from(value: Bytes) -> Self {
        Self(BytesMut::from(&value[..]))
    }
}

impl From<Vec<u8>> for Message {
    fn from(value: Vec<u8>) -> Self {
        Self(BytesMut::from(&value[..]))
    }
}

struct QuestionIter<'a> {
    raw: &'a [u8],
    offset: usize,
    lefts: u16,
}

impl<'a> Iterator for QuestionIter<'a> {
    type Item = Question<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.lefts < 1 {
            return None;
        }

        self.lefts -= 1;

        let question = Question {
            raw: self.raw,
            offset: self.offset,
        };

        self.offset += question.len();

        Some(question)
    }
}

pub struct Question<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl Question<'_> {
    pub fn len(&self) -> usize {
        self.name().len() + 4
    }

    #[inline]
    pub fn name(&self) -> Notation<'_> {
        Notation {
            raw: self.raw,
            pos: self.offset,
        }
    }

    pub fn kind(&self) -> Kind {
        let n = self.offset + self.name().len();
        Kind::parse_u16(BigEndian::read_u16(&self.raw[n..])).unwrap()
    }

    pub fn class(&self) -> QClass {
        let n = self.offset + self.name().len() + 2;
        QClass::parse_u16(BigEndian::read_u16(&self.raw[n..])).unwrap()
    }
}

struct RRIter<'a> {
    raw: &'a [u8],
    offset: usize,
    lefts: u16,
}

impl<'a> Iterator for RRIter<'a> {
    type Item = RR<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.lefts < 1 {
            return None;
        }
        self.lefts -= 1;

        let next = RR {
            raw: self.raw,
            offset: self.offset,
        };

        let size = next.len();
        self.offset += size;

        Some(next)
    }
}

/// Resource Record
pub struct RR<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl RR<'_> {
    pub fn name(&self) -> Notation<'_> {
        Notation {
            raw: self.raw,
            pos: self.offset,
        }
    }

    pub fn kind(&self) -> Kind {
        let offset = self.offset + self.name().len();
        Kind::parse_u16(BigEndian::read_u16(&self.raw[offset..])).unwrap()
    }

    pub fn class(&self) -> QClass {
        let offset = self.offset + self.name().len() + 2;
        let n = BigEndian::read_u16(&self.raw[offset..]);
        QClass::parse_u16(n).unwrap()
    }

    pub fn time_to_live(&self) -> u32 {
        let offset = self.offset + self.name().len() + 4;
        BigEndian::read_u32(&self.raw[offset..])
    }

    pub fn data(&self) -> &[u8] {
        let offset = self.offset + self.name().len() + 8;
        let size = BigEndian::read_u16(&self.raw[offset..]) as usize;
        &self.raw[offset + 2..offset + 2 + size]
    }

    pub fn data_as_cname(&self) -> Notation<'_> {
        let pos = self.offset + self.name().len() + 10;
        Notation { raw: self.raw, pos }
    }

    pub fn data_as_ipaddr(&self) -> Option<IpAddr> {
        let data = self.data();
        match data.len() {
            4 => {
                let v4 = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                Some(IpAddr::V4(v4))
            }
            16 => {
                let v6 = Ipv6Addr::new(
                    BigEndian::read_u16(data),
                    BigEndian::read_u16(&data[2..]),
                    BigEndian::read_u16(&data[4..]),
                    BigEndian::read_u16(&data[6..]),
                    BigEndian::read_u16(&data[8..]),
                    BigEndian::read_u16(&data[10..]),
                    BigEndian::read_u16(&data[12..]),
                    BigEndian::read_u16(&data[14..]),
                );
                Some(IpAddr::V6(v6))
            }
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        let n = self.name().len();
        let size = BigEndian::read_u16(&self.raw[self.offset + n + 8..]) as usize;
        n + 10 + size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notation<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl Notation<'_> {
    pub fn len(&self) -> usize {
        let mut offset = self.pos;
        let mut n = 0usize;

        loop {
            let first = self.raw[offset];
            if first & 0xc0 == 0xc0 {
                n += 2;
                break;
            }
            let size = first as usize;
            n += 1 + size;
            if size == 0 {
                break;
            }
            offset += 1 + size;
        }

        n
    }
}

impl Display for Notation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut notation = Clone::clone(self);
        match notation.next() {
            None => Ok(()),
            Some(first) => {
                write!(f, "{}", unsafe { std::str::from_utf8_unchecked(first) })?;
                for next in notation {
                    write!(f, ".{}", unsafe { std::str::from_utf8_unchecked(next) })?;
                }
                Ok(())
            }
        }
    }
}

impl<'a> Iterator for Notation<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == usize::MAX {
            return None;
        }
        let first = self.raw[self.pos];

        if first & 0xc0 == 0xc0 {
            // 1. compression pointer
            let pos = BigEndian::read_u16(&self.raw[self.pos..]) & 0x3f;
            self.pos = pos as usize;
            self.next()
        } else {
            // 2. length-based
            let size = first as usize;

            if size == 0 {
                self.pos = usize::MAX;
                return None;
            }
            let offset = self.pos + 1;
            self.pos = offset + size;
            let b = &self.raw[offset..self.pos];
            Some(b)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[test]
    fn test_decode() {
        init();

        let raw = hex::decode(
            "1afb0120000100000000000105626169647503636f6d00000100010000291000000000000000",
        )
        .unwrap();
        let dq = Message::from(Bytes::from(raw));

        assert_eq!(0x1afb, dq.id());
        assert_eq!(0x0120, dq.flags().0);
        assert!(!dq.flags().is_response());
        assert_eq!(OpCode::StandardQuery, dq.flags().opcode());

        for (i, question) in dq.questions().enumerate() {
            let name = question.name();
            let typ = question.kind();
            let class = question.class();
            info!(
                "question#{}: name={}, type={:?}, class={:?}",
                i, name, typ, class
            );
            assert_eq!(1u16, typ as u16);
            assert_eq!(QClass::IN, class);
        }
    }

    #[test]
    fn test_decode_response() {
        init();

        let message = {
            let raw = hex::decode("16068180000100020000000105626169647503636f6d0000010001c00c000100010000012200046ef24442c00c00010001000001220004279c420a0000290580000000000000").unwrap();
            Message::from(Bytes::from(raw))
        };

        for (i, answer) in message.answers().enumerate() {
            let mut v4 = [0u8; 4];
            (0..4).for_each(|i| v4[i] = answer.data()[i]);

            let kind = answer.kind();
            let class = answer.class();
            let name = answer.name();
            let addr = answer.data_as_ipaddr();
            info!(
                "answer#{}: domain={}, type={:?}, class={:?}, address={:?}",
                i, name, kind, class, addr,
            );
        }
    }

    #[test]
    fn test_youtube() {
        init();
        let msg = {
            let raw = hex::decode("e7ad81800001000e000000010377777707796f757475626503636f6d0000010001c00c00050001000000ab00160a796f75747562652d7569016c06676f6f676c65c018c02d00010001000000ad00048efa442ec02d00010001000000ad00048efa48eec02d00010001000000ad00048efabceec02d00010001000000ad00048efa488ec02d00010001000000ad00048efa48aec02d00010001000000ad00048efab00ec02d00010001000000ad00048efabd0ec02d00010001000000ad00048efad98ec02d00010001000000ad00048efb282ec02d00010001000000ad00048efa440ec02d00010001000000ad0004acd90c8ec02d00010001000000ad0004acd90e4ec02d00010001000000ad00048efa446e0000290200000000000000").unwrap();
            Message::from(raw)
        };

        for (i, answer) in msg.answers().enumerate() {
            match answer.kind() {
                Kind::A => {
                    info!("A: {:?}", answer.data_as_ipaddr());
                }
                Kind::CNAME => {
                    info!("CNAME: {}", answer.data_as_cname());
                }
                _ => (),
            }
        }
    }

    #[test]
    fn test_big() {
        init();

        let raw = hex::decode("e7ad81800001000e000000010377777707796f757475626503636f6d0000010001c00c00050001000000ab00160a796f75747562652d7569016c06676f6f676c65c018c02d00010001000000ad00048efa442ec02d00010001000000ad00048efa48eec02d00010001000000ad00048efabceec02d00010001000000ad00048efa488ec02d00010001000000ad00048efa48aec02d00010001000000ad00048efab00ec02d00010001000000ad00048efabd0ec02d00010001000000ad00048efad98ec02d00010001000000ad00048efb282ec02d00010001000000ad00048efa440ec02d00010001000000ad0004acd90c8ec02d00010001000000ad0004acd90e4ec02d00010001000000ad00048efa446e0000290200000000000000").unwrap();

        let offset = 113 - 68;
        let notation = Notation {
            raw: &raw[..],
            pos: offset,
        };

        assert_eq!(22, notation.len());

        let cname = format!("{}", &notation);
        info!("CNAME: {}", &cname);
        assert_eq!("youtube-ui.l.google.com", &cname);
    }

    #[test]
    fn test_flags() {
        init();

        let msg = {
            let raw = hex::decode(
                "6e1c818200010000000000010462696e6702636e00000100010000290580000000000000",
            )
            .unwrap();
            Message::from(raw)
        };

        let f = msg.flags();
        assert_eq!(0x8182, f.0);
        assert!(f.is_response(), "should be response");
        assert_eq!(
            OpCode::StandardQuery,
            f.opcode(),
            "should be standard query"
        );
        assert!(!f.is_authoritative());
        assert!(!f.is_message_truncated());
        assert!(f.is_recursive_query());
        assert!(f.is_recursion_available());
        assert_eq!(0, f.reserved());
        assert_eq!(RCode::ServerFailure, f.response_code());
    }
}
