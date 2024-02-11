use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};

// http://www.tcpipguide.com/free/t_DNSMessagingandMessageResourceRecordandMasterFileF.htm

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Type {
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

impl Type {
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
    Standard,
    Inverse,
}

pub struct Flags(u16);

impl Flags {
    pub fn is_response(&self) -> bool {
        self.0 & 0x0001 != 0
    }

    pub fn opcode(&self) -> OpCode {
        match self.0 & 0b0000_0000_0001_1110 {
            0b0000_0000_0000_0000 => OpCode::Standard,
            0b0000_0000_0000_0100 => OpCode::Inverse,
            _ => unreachable!(),
        }
    }

    pub fn is_authoritative(&self) -> bool {
        (self.0 >> 6) & 0x01 != 0
    }

    pub fn is_message_truncated(&self) -> bool {
        (self.0 >> 7) & 0x01 != 0
    }

    pub fn is_recursive_query(&self) -> bool {
        (self.0 >> 8) & 0x01 != 0
    }

    pub fn is_recursion_available(&self) -> bool {
        (self.0 >> 9) & 0x01 != 0
    }
}

// https://www.firewall.cx/networking/network-protocols/dns-protocol/protocols-dns-query.html
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Message(pub(crate) BytesMut);

impl Message {
    pub fn id(&self) -> u16 {
        BigEndian::read_u16(&self.0[..])
    }

    pub fn set_id(&mut self, id: u16) {
        BigEndian::write_u16(&mut self.0[..], id);
    }

    pub fn flags(&self) -> Flags {
        Flags(BigEndian::read_u16(&self.0[2..]))
    }

    pub fn questions(&self) -> impl Iterator<Item = Question<'_>> {
        let questions_num = BigEndian::read_u16(&self.0[4..]);
        QuestionIter {
            raw: &self.0[12..],
            lefts: questions_num,
        }
    }

    pub fn answers(&self) -> impl Iterator<Item = RR<'_>> {
        let n = BigEndian::read_u16(&self.0[6..]);

        let mut offset = 12;
        for next in self.questions() {
            offset += next.len();
        }

        RRIter {
            raw: &self.0[..],
            offset,
            lefts: n,
        }
    }

    pub fn authority(&self) -> u16 {
        BigEndian::read_u16(&self.0[8..])
    }

    pub fn additional(&self) -> u16 {
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

pub struct QuestionIter<'a> {
    raw: &'a [u8],
    lefts: u16,
}

impl<'a> Iterator for QuestionIter<'a> {
    type Item = Question<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.lefts < 1 {
            return None;
        }

        self.lefts -= 1;

        let question = Question(self.raw);

        self.raw = &self.raw[question.len()..];

        Some(question)
    }
}

pub struct Question<'a>(&'a [u8]);

impl Question<'_> {
    pub fn len(&self) -> usize {
        self.get_domain_len() + 4
    }

    pub fn name(&self) -> impl Iterator<Item = &'_ [u8]> {
        DomainIter(self.0)
    }

    pub fn typ(&self) -> Type {
        Type::parse_u16(BigEndian::read_u16(&self.0[self.get_domain_len()..])).unwrap()
    }

    pub fn class(&self) -> QClass {
        QClass::parse_u16(BigEndian::read_u16(&self.0[self.get_domain_len() + 2..])).unwrap()
    }

    #[inline(always)]
    fn get_domain_len(&self) -> usize {
        let mut offset = 1usize;
        for next in self.name() {
            offset += next.len() + 1;
        }
        offset
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DomainIter<'a>(&'a [u8]);

impl<'a> Iterator for DomainIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let size = self.0[0] as usize;

        if size == 0 {
            return None;
        }

        let domain = &self.0[1..1 + size];

        self.0 = &self.0[1 + size..];

        Some(domain)
    }
}

enum RRName<'a> {
    Normal(DomainIter<'a>),
    Reference(u16),
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

pub struct RR<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl RR<'_> {
    pub fn name(&self) -> impl Iterator<Item = &[u8]> {
        match self.rrname() {
            RRName::Normal(d) => d,
            RRName::Reference(offset) => DomainIter(&self.raw[offset as usize..]),
        }
    }

    pub fn typ(&self) -> Type {
        let b = &self.raw[self.offset..];
        let offset = self.get_name_len();
        Type::parse_u16(BigEndian::read_u16(&b[offset..])).unwrap()
    }

    pub fn class(&self) -> QClass {
        let b = &self.raw[self.offset..];
        let offset = self.get_name_len();
        let n = BigEndian::read_u16(&b[offset + 2..]);
        QClass::parse_u16(n).unwrap()
    }

    pub fn time_to_live(&self) -> u32 {
        let b = &self.raw[self.offset..];
        let offset = self.get_name_len();
        BigEndian::read_u32(&b[offset + 4..])
    }

    pub fn data(&self) -> &[u8] {
        let b = &self.raw[self.offset..];
        let offset = self.get_name_len();
        let size = BigEndian::read_u16(&b[offset + 8..]) as usize;
        &b[offset + 10..offset + 10 + size]
    }

    pub fn len(&self) -> usize {
        let b = &self.raw[self.offset..];
        let offset = self.get_name_len();
        let size = BigEndian::read_u16(&b[offset + 8..]) as usize;
        offset + 10 + size
    }

    #[inline(always)]
    fn rrname(&self) -> RRName<'_> {
        let b = &self.raw[self.offset..];
        if b[0] & 0xc0 == 0xc0 {
            RRName::Reference(BigEndian::read_u16(b) & 0x3f)
        } else {
            RRName::Normal(DomainIter(b))
        }
    }

    #[inline(always)]
    fn get_name_len(&self) -> usize {
        match self.rrname() {
            RRName::Normal(it) => {
                let mut offset = 1usize;
                for next in it {
                    offset += next.len() + 1;
                }
                offset
            }
            RRName::Reference(_) => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

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
        assert_eq!(OpCode::Standard, dq.flags().opcode());

        for question in dq.questions() {
            for (i, next) in question.name().enumerate() {
                info!("#{}: {}", i, String::from_utf8_lossy(next));
            }
            assert_eq!(1u16, question.typ() as u16);
            assert_eq!(QClass::IN, question.class());
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
            let mut v = vec![];
            for (j, next) in answer.name().enumerate() {
                if j > 0 {
                    v.push(b'.');
                }
                v.extend_from_slice(next);
            }

            let mut v4 = [0u8; 4];
            (0..4).for_each(|i| v4[i] = answer.data()[i]);

            let typ = answer.typ();
            let class = answer.class();

            info!(
                "answer#{}: domain={}, type={:?}, class={:?}, address={}",
                i,
                String::from_utf8_lossy(&v[..]),
                answer.typ(),
                answer.class(),
                Ipv4Addr::from(v4),
            );
        }
    }

    // #[test]
    // fn test_rr() {
    //     init();
    //     let raw = hex::decode("c00c000100010000019e0004279c420a").unwrap();
    //     let rr = RR::from(&raw[..]);
    //     let name = rr.name();
    //     assert_eq!(RRName::Reference(0x000c), name);
    //     assert_eq!(Type::A, rr.typ());
    //     assert_eq!(QClass::IN, rr.class());
    //     assert_eq!(414, rr.time_to_live());
    //     assert_eq!(&[39, 156, 66, 10], rr.data());
    // }
}
