use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use once_cell::sync::Lazy;
use regex::Regex;

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
pub enum Class {
    /// the Internet
    IN = 1,
    /// the CSNET
    CS = 2,
    /// the CHAOS, see https://en.wikipedia.org/wiki/Chaosnet
    CH = 3,
    /// Hesiod, see https://en.wikipedia.org/wiki/Hesiod_(name_service)
    HS = 4,
}

impl Class {
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

pub struct FlagsBuilder(u16);

impl FlagsBuilder {
    pub fn request(mut self) -> Self {
        self.0 &= 0x8000 - 1;
        self
    }

    pub fn response(mut self) -> Self {
        self.0 |= 0x8000;
        self
    }

    pub fn opcode(mut self, opcode: OpCode) -> Self {
        self.0 &= 0x87ff;
        self.0 |= (opcode as u16) << 11;
        self
    }

    pub fn rcode(mut self, c: RCode) -> Self {
        self.0 &= 0xfff0;
        self.0 |= c as u16;
        self
    }

    pub fn authoritative(mut self, enabled: bool) -> Self {
        const MASK: u16 = 1 << 10;
        if enabled {
            self.0 |= MASK;
        } else {
            self.0 &= !MASK;
        }
        self
    }

    pub fn truncated(mut self, enabled: bool) -> Self {
        const MASK: u16 = 1 << 9;
        if enabled {
            self.0 |= MASK;
        } else {
            self.0 &= !MASK;
        }
        self
    }

    pub fn recursive_query(mut self, enabled: bool) -> Self {
        const MASK: u16 = 1 << 8;
        if enabled {
            self.0 |= MASK;
        } else {
            self.0 &= !MASK;
        }
        self
    }

    pub fn recursive_available(mut self, enabled: bool) -> Self {
        const MASK: u16 = 1 << 7;
        if enabled {
            self.0 |= MASK;
        } else {
            self.0 &= !MASK;
        }
        self
    }

    pub fn build(self) -> Flags {
        Flags(self.0)
    }
}

/// DNS Message Flags:
///  - http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Flags(u16);

impl Flags {
    pub fn builder() -> FlagsBuilder {
        FlagsBuilder(0)
    }

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

struct Authority<'a> {
    name: &'a str,
    kind: Kind,
    class: Class,
    ttl: u32,
    primary_name_server: &'a str,
    responsible_authority_mailbox: &'a str,
    refresh_interval: u32,
    retry_interval: u32,
    expire_limit: u32,
    minimum_ttl: u32,
}

struct Answer<'a> {
    name: &'a str,
    kind: Kind,
    class: Class,
    ttl: u32,
    data: &'a [u8],
}

struct Additional {}

struct Query<'a> {
    name: &'a str,
    kind: Kind,
    class: Class,
}

#[derive(Default)]
pub struct MessageBuilder<'a> {
    id: u16,
    flags: Flags,
    queries: Vec<Query<'a>>,
    answers: Vec<Answer<'a>>,
    authorities: Vec<Authority<'a>>,
    additionals: Vec<Additional>,
}

impl<'a> MessageBuilder<'a> {
    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn flags(mut self, flags: Flags) -> Self {
        self.flags = flags;
        self
    }

    pub fn question<'b>(mut self, name: &'b str, kind: Kind, class: Class) -> Self
    where
        'b: 'a,
    {
        self.queries.push(Query { name, kind, class });
        self
    }

    pub fn build(self) -> crate::Result<Message> {
        let Self {
            id,
            flags,
            queries,
            answers,
            authorities,
            additionals,
        } = self;

        let mut b = BytesMut::with_capacity(1536);
        b.put_u16(id);
        b.put_u16(flags.0);

        b.put_u16(queries.len() as u16);
        b.put_u16(answers.len() as u16);
        b.put_u16(authorities.len() as u16);
        b.put_u16(additionals.len() as u16);

        for next in queries {
            if !is_valid_domain(next.name) {
                bail!("invalid question name '{}'", next.name);
            }
            for label in next
                .name
                .split('.')
                .filter(|it| !it.is_empty())
                .map(|it| it.as_bytes())
            {
                b.put_u8(label.len() as u8);
                b.put_slice(label);
            }
            b.put_u8(0);
            b.put_u16(next.kind as u16);
            b.put_u16(next.class as u16);
        }

        for next in answers {
            // TODO: write answer
        }

        for next in authorities {
            // TODO: write authority
        }

        for next in additionals {
            // TODO: write additional
        }

        Ok(Message(b))
    }
}

/// DNS message, see links below:
///  - https://www.firewall.cx/networking/network-protocols/dns-protocol/protocols-dns-query.html
///  - http://www.tcpipguide.com/free/t_DNSMessagingandMessageResourceRecordandMasterFileF.htm
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Message(pub(crate) BytesMut);

impl Message {
    pub fn builder<'a>() -> MessageBuilder<'a> {
        Default::default()
    }

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

    pub fn authorities(&self) -> impl Iterator<Item = RR<'_>> {
        let mut offset = 12;
        for next in self.questions() {
            offset += next.len();
        }
        for next in self.answers() {
            offset += next.len();
        }

        RRIter {
            raw: &self.0[..],
            offset,
            lefts: self.authority_count(),
        }
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

    pub fn class(&self) -> Class {
        let n = self.offset + self.name().len() + 2;
        Class::parse_u16(BigEndian::read_u16(&self.raw[n..])).unwrap()
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

    pub fn class(&self) -> Class {
        let offset = self.offset + self.name().len() + 2;
        let n = BigEndian::read_u16(&self.raw[offset..]);
        Class::parse_u16(n).unwrap()
    }

    pub fn time_to_live(&self) -> u32 {
        let offset = self.offset + self.name().len() + 4;
        BigEndian::read_u32(&self.raw[offset..])
    }

    #[inline(always)]
    fn data_offset_and_size(&self) -> (usize, usize) {
        let offset = self.offset + self.name().len() + 8;
        let size = BigEndian::read_u16(&self.raw[offset..]) as usize;
        (offset + 2, size)
    }

    pub fn rdata(&self) -> crate::Result<RData<'_>> {
        let (offset, size) = self.data_offset_and_size();
        Ok(match self.kind() {
            Kind::A => {
                if size != 4 {
                    bail!(
                        "invalid RR format: size of type(A) should be 4, actual is {}",
                        size
                    );
                }
                RData::A(A(&self.raw[offset..offset + size]))
            }
            Kind::CNAME => RData::CNAME(CNAME {
                raw: &self.raw[..offset + size],
                offset,
                size,
            }),
            Kind::SOA => RData::SOA(SOA {
                raw: &self.raw[..offset + size],
                offset,
                size,
            }),
            Kind::PTR => RData::PTR(PTR {
                raw: &self.raw[..offset + size],
                offset,
                size,
            }),
            Kind::MX => RData::MX(MX {
                raw: &self.raw[..offset + size],
                offset,
                size,
            }),
            _ => RData::UNKNOWN(&self.raw[offset..offset + size]),
        })
    }

    pub fn data(&self) -> &[u8] {
        let (offset, size) = self.data_offset_and_size();
        &self.raw[offset..offset + size]
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

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum RData<'a> {
    A(A<'a>),
    CNAME(CNAME<'a>),
    MX(MX<'a>),
    SOA(SOA<'a>),
    PTR(PTR<'a>),
    UNKNOWN(&'a [u8]),
}

impl<'a> Display for RData<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RData::A(a) => write!(f, "RData({})", a),
            RData::CNAME(it) => write!(f, "RData({})", it),
            RData::MX(it) => write!(f, "RData({})", it),
            RData::SOA(it) => write!(f, "RData({})", it),
            RData::PTR(it) => write!(f, "RData({})", it),
            RData::UNKNOWN(b) => write!(f, "RData(UNKNOWN {:?})", b),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct A<'a>(&'a [u8]);

impl A<'_> {
    pub fn ipaddr(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl<'a> Display for A<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "A {}.{}.{}.{}",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct MX<'a> {
    raw: &'a [u8],
    offset: usize,
    size: usize,
}

impl MX<'_> {
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn preference(&self) -> u16 {
        BigEndian::read_u16(&self.raw[self.offset..])
    }

    pub fn mail_exchange(&self) -> Notation<'_> {
        Notation {
            raw: &self.raw[..self.offset + self.size],
            pos: 2 + self.offset,
        }
    }
}

impl<'a> Display for MX<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MX {} {}", self.preference(), self.mail_exchange())
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct PTR<'a> {
    raw: &'a [u8],
    offset: usize,
    size: usize,
}

impl PTR<'_> {
    pub fn domain_name(&self) -> Notation<'_> {
        Notation {
            raw: self.raw,
            pos: self.offset,
        }
    }
}

impl Display for PTR<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PTR {}", self.domain_name())
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct CNAME<'a> {
    raw: &'a [u8],
    offset: usize,
    size: usize,
}

impl CNAME<'_> {
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn cname(&self) -> Notation<'_> {
        Notation {
            raw: &self.raw[..self.offset + self.size],
            pos: self.offset,
        }
    }
}

impl<'a> Display for CNAME<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CNAME {}", self.cname())
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct SOA<'a> {
    raw: &'a [u8],
    offset: usize,
    size: usize,
}

impl SOA<'_> {
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn primary_nameserver(&self) -> Notation<'_> {
        Notation {
            raw: self.raw,
            pos: self.offset,
        }
    }

    pub fn responsible_authority_mailbox(&self) -> Notation<'_> {
        Notation {
            raw: self.raw,
            pos: self.offset + self.primary_nameserver().len(),
        }
    }

    pub fn serial_number(&self) -> u32 {
        let offset = self.offset
            + self.primary_nameserver().len()
            + self.responsible_authority_mailbox().len();
        BigEndian::read_u32(&self.raw[offset..])
    }

    pub fn refresh_interval(&self) -> u32 {
        let offset = self.offset
            + self.primary_nameserver().len()
            + self.responsible_authority_mailbox().len()
            + 4;
        BigEndian::read_u32(&self.raw[offset..])
    }

    pub fn retry_interval(&self) -> u32 {
        let offset = self.offset
            + self.primary_nameserver().len()
            + self.responsible_authority_mailbox().len()
            + 8;
        BigEndian::read_u32(&self.raw[offset..])
    }

    pub fn expire_limit(&self) -> u32 {
        let offset = self.offset
            + self.primary_nameserver().len()
            + self.responsible_authority_mailbox().len()
            + 12;
        BigEndian::read_u32(&self.raw[offset..])
    }

    pub fn minimum_ttl(&self) -> u32 {
        let offset = self.offset
            + self.primary_nameserver().len()
            + self.responsible_authority_mailbox().len()
            + 16;
        BigEndian::read_u32(&self.raw[offset..])
    }
}

impl<'a> Display for SOA<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SOA {} {} {} {} {} {} {}",
            self.primary_nameserver(),
            self.responsible_authority_mailbox(),
            self.serial_number(),
            self.refresh_interval(),
            self.retry_interval(),
            self.expire_limit(),
            self.minimum_ttl(),
        )
    }
}

fn is_valid_domain(domain: &str) -> bool {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new("^([a-z0-9]{1,63})(\\.[a-z0-9]{1,63})+\\.?$").unwrap());
    RE.is_match(domain)
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
            assert_eq!(Class::IN, class);
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
            let kind = answer.kind();
            let class = answer.class();
            let name = answer.name();
            let rdata = answer.rdata().unwrap();
            info!(
                "answer#{}: domain={}, type={:?}, class={:?}, rdata={}",
                i, name, kind, class, rdata,
            );
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

    #[test]
    fn test_rdata_ptr() {
        init();
        let msg = {
            let raw = hex::decode("042f81800001000100000001013101310131013107696e2d61646472046172706100000c0001c00c000c0001000007080011036f6e65036f6e65036f6e65036f6e65000000290580000000000000").unwrap();
            Message::from(raw)
        };

        assert_eq!(1, msg.answer_count());

        assert!(msg.answers().next().is_some_and(|answer| {
            assert_eq!(Kind::PTR, answer.kind());
            assert_eq!(Class::IN, answer.class());
            let rdata = answer.rdata();
            rdata.is_ok_and(|rdata| {
                let mut is_ptr = false;
                if let RData::PTR(ptr) = &rdata {
                    is_ptr = true;
                    assert_eq!("one.one.one.one", &format!("{}", ptr.domain_name()));
                }
                is_ptr
            })
        }))
    }

    #[test]
    fn test_rdata_mx() {
        init();

        let msg = {
            let raw = hex::decode("63998180000100010000000107796f757475626503636f6d00000f0001c00c000f00010000012c0010000004736d747006676f6f676c65c0140000290200000000000000").unwrap();
            Message::from(raw)
        };

        assert_eq!(1, msg.answer_count());

        assert!(msg.answers().next().is_some_and(|answer| {
            answer.rdata().is_ok_and(|rdata| {
                info!("rdata: {}", rdata);

                let mut ok = false;
                if let RData::MX(mx) = rdata {
                    ok = true;
                    assert_eq!(16, mx.len());
                    assert_eq!(0, mx.preference());
                    assert_eq!("smtp.google.com", &format!("{}", mx.mail_exchange()));
                }
                ok
            })
        }))
    }

    #[test]
    fn test_rdata_cname() {
        init();
        let msg = {
            let raw = hex::decode("e7ad81800001000e000000010377777707796f757475626503636f6d0000010001c00c00050001000000ab00160a796f75747562652d7569016c06676f6f676c65c018c02d00010001000000ad00048efa442ec02d00010001000000ad00048efa48eec02d00010001000000ad00048efabceec02d00010001000000ad00048efa488ec02d00010001000000ad00048efa48aec02d00010001000000ad00048efab00ec02d00010001000000ad00048efabd0ec02d00010001000000ad00048efad98ec02d00010001000000ad00048efb282ec02d00010001000000ad00048efa440ec02d00010001000000ad0004acd90c8ec02d00010001000000ad0004acd90e4ec02d00010001000000ad00048efa446e0000290200000000000000").unwrap();
            Message::from(raw)
        };

        for (i, answer) in msg.answers().enumerate() {
            let rdata = answer.rdata();
            assert!(rdata.is_ok());
            let rdata = rdata.unwrap();

            info!("answer#{}: rdata={}", i, &rdata);

            match answer.kind() {
                Kind::A => {
                    assert!(matches!(rdata, RData::A(_)));
                }
                Kind::CNAME => {
                    assert!(matches!(rdata, RData::CNAME(_)));
                }
                _ => (),
            }
        }
    }

    #[test]
    fn test_soa() {
        init();

        let msg = {
            let raw = hex::decode("b032818000010001000100010377777707796f757475626503636f6d0000060001c00c000500010000012c00160a796f75747562652d7569016c06676f6f676c65c018c038000600010000003c0026036e7331c03a09646e732d61646d696ec03a243c546e0000038400000384000007080000003c0000290200000000000000").unwrap();
            Message::from(raw)
        };

        assert_eq!(1, msg.authority_count());

        for next in msg.authorities() {
            let rdata = next.rdata();

            if let Ok(RData::SOA(soa)) = rdata {
                info!("{}", &soa);
                assert_eq!("ns1.google.com", &format!("{}", soa.primary_nameserver()));
                assert_eq!(
                    "dns-admin.google.com",
                    &format!("{}", soa.responsible_authority_mailbox())
                );
                assert_eq!(607933550, soa.serial_number());
                assert_eq!(900, soa.refresh_interval());
                assert_eq!(900, soa.retry_interval());
                assert_eq!(1800, soa.expire_limit());
                assert_eq!(60, soa.minimum_ttl());
            }
        }
    }

    #[test]
    fn test_message_builder() {
        init();

        // good
        {
            let domain = "google.com";
            let msg = Message::builder()
                .id(1234)
                .question(&format!("{}.", domain), Kind::A, Class::IN)
                .build();

            assert!(msg.is_ok_and(|msg| {
                assert_eq!(1234, msg.id());
                assert_eq!(1, msg.question_count());
                assert!(msg.questions().next().is_some_and(|it| {
                    assert_eq!(domain, &format!("{}", it.name()));
                    true
                }));

                true
            }));
        }

        // bad
        {
            let msg = Message::builder()
                .id(1234)
                .question("It's a bad domain", Kind::A, Class::IN)
                .build();
            assert!(msg.is_err());
        }
    }

    #[test]
    fn test_flags_builder() {
        let flags = Flags::builder()
            .request()
            .recursive_query(true)
            .opcode(OpCode::StandardQuery)
            .build();

        assert!(!flags.is_response());
        assert_eq!(OpCode::StandardQuery, flags.opcode());
        assert!(flags.is_recursive_query());
        assert!(!flags.is_recursion_available());
        assert!(!flags.is_authoritative());
        assert!(!flags.is_message_truncated());
        assert_eq!(0, flags.reserved());
        assert_eq!(RCode::NoError, flags.response_code());
    }
}
