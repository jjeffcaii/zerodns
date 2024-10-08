use std::fmt::{Debug, Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use ahash::HashMap;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use once_cell::sync::Lazy;
use regex::Regex;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

macro_rules! parse_u16 {
    ($name:ident) => {
        impl $name {
            pub fn parse_u16(code: u16) -> Option<$name> {
                static IDX: Lazy<HashMap<u16, $name>> = Lazy::new(|| {
                    let mut m = HashMap::with_capacity_and_hasher(
                        $name::iter().len(),
                        ahash::RandomState::default(),
                    );
                    $name::iter().for_each(|next| {
                        m.insert(next as u16, next);
                    });
                    m
                });
                IDX.get(&code).cloned()
            }
        }
    };
}

parse_u16!(RCode);
parse_u16!(Class);
parse_u16!(OpCode);
parse_u16!(Kind);

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, Hash)]
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

/// dns record types, see also https://en.wikipedia.org/wiki/List_of_DNS_record_types
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, Hash)]
pub enum Kind {
    /// RFC 1035, Address record
    A = 1,
    /// RFC 3596, IPv6 address record
    AAAA = 28,
    /// RFC 1183, AFS database record
    AFSDB = 18,
    /// RFC 3123, Address Prefix List
    APL = 42,
    /// RFC 6844, Certification Authority Authorization
    CAA = 257,
    /// RFC 7344, Child copy of DNSKEY record, for transfer to parent
    CDNSKEY = 60,
    /// RFC 7344, Child DS
    CDS = 59,
    /// RFC 4398, Certificate record
    CERT = 37,
    /// RFC 1035, Canonical name record
    CNAME = 5,
    /// RFC 7477, Child-to-Parent Synchronization
    CSYNC = 62,
    /// RFC 4701, DHCP identifier
    DHCID = 49,
    /// RFC 4431, DNSSEC Lookaside Validation record
    DLV = 32769,
    /// RFC 6672, Delegation name record
    DNAME = 39,
    /// RFC 4034, DNS Key record
    DNSKEY = 48,
    /// RFC 4034, Delegation signer
    DS = 43,
    /// RFC 7043, MAC address (EUI-48)
    EUI48 = 108,
    /// RFC 7043, MAC address (EUI-64)
    EUI64 = 109,
    /// RFC 8482, Host Information
    HINFO = 13,
    /// RFC 8005, Host Identity Protocol
    HIP = 55,
    /// RFC 9460, HTTPS Binding
    HTTPS = 65,
    /// RFC 4025, IPsec Key
    IPSECKEY = 45,
    /// RFC 2535 and RFC 2930, Key record
    KEY = 25,
    /// RFC 2230, Key Exchanger record
    KX = 36,
    /// RFC 1876, Location record
    LOC = 29,
    /// RFC 1035 and RFC 7505, Mail exchange record
    MX = 15,
    /// RFC 3403, Naming Authority Pointer
    NAPTR = 35,
    /// RFC 1035, Name server record
    NS = 2,
    /// RFC 4034, Next Secure record
    NSEC = 47,
    /// RFC 5155, Next Secure record version 3
    NSEC3 = 50,
    /// RFC 5155, NSEC3 parameters
    NSEC3PARAM = 51,
    /// RFC 7929, OpenPGP public key record
    OPENPGPKEY = 61,
    /// RFC 1035, PTR Resource Record
    PTR = 12,
    /// RFC 4034, DNSSEC signature
    RRSIG = 46,
    /// RFC 1183, Responsible Person
    RP = 17,
    /// RFC 2535, Signature
    SIG = 24,
    /// RFC 8162, S/MIME cert association
    SMIMEA = 53,
    /// RFC 1035 and RFC 2308, Start of [a zone of] authority record
    SOA = 6,
    /// RFC 2782, Service locator
    SRV = 33,
    /// RFC 4255, SSH Public Key Fingerprint
    SSHFP = 44,
    /// RFC 9460, Service Binding
    SVCB = 64,
    /// DNSSEC Trust Authorities
    TA = 32768,
    /// RFC 2930, Transaction Key record
    TKEY = 249,
    /// RFC 6698, TLSA certificate association
    TLSA = 52,
    /// RFC 2845, Transaction Signature
    TSIG = 250,
    /// RFC 1035, Text record
    TXT = 16,
    /// RFC 7553, Uniform Resource Identifier
    URI = 256,
    /// RFC 8976, Message Digests for DNS Zones
    ZONEMD = 63,
    /// RFC 1035, All cached records
    ANY = 255,
    /// RFC 1035, Authoritative Zone Transfer
    AXFR = 252,
    /// RFC 1996, Incremental Zone Transfer
    IXFR = 251,
    /// RFC 6891, Option, This is a pseudo-record type needed to support EDNS.
    OPT = 41,
}

impl Display for Kind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Kind::A => f.write_str("A"),
            Kind::AAAA => f.write_str("AAAA"),
            Kind::AFSDB => f.write_str("AFSDB"),
            Kind::APL => f.write_str("APL"),
            Kind::CAA => f.write_str("CAA"),
            Kind::CDNSKEY => f.write_str("CDNSKEY"),
            Kind::CDS => f.write_str("CDS"),
            Kind::CERT => f.write_str("CERT"),
            Kind::CNAME => f.write_str("CNAME"),
            Kind::CSYNC => f.write_str("CSYNC"),
            Kind::DHCID => f.write_str("DHCID"),
            Kind::DLV => f.write_str("DLV"),
            Kind::DNAME => f.write_str("DNAME"),
            Kind::DNSKEY => f.write_str("DNSKEY"),
            Kind::DS => f.write_str("DS"),
            Kind::EUI48 => f.write_str("EUI48"),
            Kind::EUI64 => f.write_str("EUI64"),
            Kind::HINFO => f.write_str("HINFO"),
            Kind::HIP => f.write_str("HIP"),
            Kind::HTTPS => f.write_str("HTTPS"),
            Kind::IPSECKEY => f.write_str("IPSECKEY"),
            Kind::KEY => f.write_str("KEY"),
            Kind::KX => f.write_str("KX"),
            Kind::LOC => f.write_str("LOC"),
            Kind::MX => f.write_str("MX"),
            Kind::NAPTR => f.write_str("NAPTR"),
            Kind::NS => f.write_str("NS"),
            Kind::NSEC => f.write_str("NSEC"),
            Kind::NSEC3 => f.write_str("NSEC3"),
            Kind::NSEC3PARAM => f.write_str("NSEC3PARAM"),
            Kind::OPENPGPKEY => f.write_str("OPENPGPKEY"),
            Kind::PTR => f.write_str("PTR"),
            Kind::RRSIG => f.write_str("RSIG"),
            Kind::RP => f.write_str("RP"),
            Kind::SIG => f.write_str("SIG"),
            Kind::SMIMEA => f.write_str("SMIMEA"),
            Kind::SOA => f.write_str("SOA"),
            Kind::SRV => f.write_str("SRV"),
            Kind::SSHFP => f.write_str("SSHFP"),
            Kind::SVCB => f.write_str("SVCB"),
            Kind::TA => f.write_str("TA"),
            Kind::TKEY => f.write_str("TKEY"),
            Kind::TLSA => f.write_str("TLSA"),
            Kind::TSIG => f.write_str("TSIG"),
            Kind::TXT => f.write_str("TXT"),
            Kind::URI => f.write_str("URI"),
            Kind::ZONEMD => f.write_str("ZONEMD"),
            Kind::ANY => f.write_str("ANY"),
            Kind::AXFR => f.write_str("AXFR"),
            Kind::IXFR => f.write_str("IXFR"),
            Kind::OPT => f.write_str("OPT"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, Hash)]
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

impl Display for Class {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Class::IN => f.write_str("IN"),
            Class::CS => f.write_str("CS"),
            Class::CH => f.write_str("CH"),
            Class::HS => f.write_str("HS"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, Hash)]
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
        OpCode::parse_u16((self.0 >> 11) & 0x000f).expect("Invalid Opcode!")
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

impl Into<Bytes> for Message {
    fn into(self) -> Bytes {
        self.0.freeze()
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn name(&self) -> Notation<'_> {
        Notation::new(self.raw, self.offset)
    }

    pub fn kind(&self) -> Kind {
        let n = self.offset + self.name().len();
        Kind::parse_u16(BigEndian::read_u16(&self.raw[n..])).expect("Invalid question type!")
    }

    pub fn class(&self) -> Class {
        let n = self.offset + self.name().len() + 2;
        Class::parse_u16(BigEndian::read_u16(&self.raw[n..])).expect("Invalid question class!")
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
        Notation::new(self.raw, self.offset)
    }

    pub fn kind(&self) -> Kind {
        let offset = self.offset + self.name().len();
        let code = BigEndian::read_u16(&self.raw[offset..]);
        Kind::parse_u16(code).expect("Invalid RR type!")
    }

    pub fn class(&self) -> Class {
        let offset = self.offset + self.name().len() + 2;
        let n = BigEndian::read_u16(&self.raw[offset..]);
        Class::parse_u16(n).expect("Invalid RR class!")
    }

    #[inline(always)]
    pub(crate) fn time_to_live_pos(&self) -> usize {
        self.offset + self.name().len() + 4
    }

    pub fn time_to_live(&self) -> u32 {
        let offset = self.time_to_live_pos();
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
            Kind::AAAA => {
                if size != 16 {
                    bail!(
                        "invalid RR format: size of type(AAAA) should be 16, actual is {}",
                        size
                    );
                }
                RData::AAAA(AAAA(&self.raw[offset..offset + size]))
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
            Kind::NS => RData::NS(NS {
                raw: &self.raw[..offset + size],
                offset,
                size,
            }),
            Kind::HTTPS => RData::HTTPS(HTTPS {
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    offset: usize,
    cur: usize,
}

impl<'a> Notation<'a> {
    fn new(raw: &'a [u8], offset: usize) -> Self {
        Self {
            raw,
            offset,
            cur: offset,
        }
    }
}

impl Notation<'_> {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        let mut offset = self.offset;
        let mut n = 0usize;

        loop {
            if offset >= self.raw.len() {
                error!(
                    "overflow: raw={}, offset={}, current={}",
                    hex::encode(self.raw),
                    self.offset,
                    offset
                );
            }
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
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut notation = Self {
            raw: self.raw,
            offset: self.offset,
            cur: self.offset,
        };
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
        if self.cur == usize::MAX {
            return None;
        }
        let first = self.raw[self.cur];

        if first & 0xc0 == 0xc0 {
            // 1. compression pointer
            let pos = BigEndian::read_u16(&self.raw[self.cur..]) & !0xc000;
            self.cur = pos as usize;
            self.next()
        } else {
            // 2. length-based
            let size = first as usize;

            if size == 0 {
                self.cur = usize::MAX;
                return None;
            }
            let offset = self.cur + 1;
            self.cur = offset + size;
            let b = &self.raw[offset..self.cur];
            Some(b)
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum RData<'a> {
    A(A<'a>),
    AAAA(AAAA<'a>),
    CNAME(CNAME<'a>),
    MX(MX<'a>),
    SOA(SOA<'a>),
    PTR(PTR<'a>),
    NS(NS<'a>),
    HTTPS(HTTPS<'a>),
    UNKNOWN(&'a [u8]),
}

impl<'a> Display for RData<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RData::A(it) => write!(f, "{}", it),
            RData::CNAME(it) => write!(f, "{}", it),
            RData::MX(it) => write!(f, "{}", it),
            RData::SOA(it) => write!(f, "{}", it),
            RData::PTR(it) => write!(f, "{}", it),
            RData::AAAA(it) => write!(f, "{}", it),
            RData::NS(it) => write!(f, "{}", it),
            RData::HTTPS(it) => write!(f, "{}", it),
            RData::UNKNOWN(it) => write!(f, "UNKNOWN({:?})", it),
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
        write!(f, "{}", self.ipaddr())
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct HTTPS<'a> {
    raw: &'a [u8],
    offset: usize,
    size: usize,
}

impl HTTPS<'_> {
    pub fn priority(&self) -> u16 {
        BigEndian::read_u16(&self.raw[self.offset..])
    }

    pub fn target_name(&self) -> Notation<'_> {
        Notation::new(self.raw, self.offset + 2)
    }

    pub fn params(&self) -> impl Iterator<Item = HttpsSvcParam<'_>> {
        HttpsSvcParamIter(&self.raw[self.offset + 2 + self.target_name().len()..])
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SvcParamKey {
    ALPN,
    NODEFAULTALPN,
    PORT,
    IPV4HINT,
    ECHCONFIG,
    IPV6HINT,
    PRIVATE(u16),
    RESERVED,
}

impl Display for SvcParamKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SvcParamKey::ALPN => write!(f, "alpn"),
            SvcParamKey::NODEFAULTALPN => write!(f, "no-default-alpn"),
            SvcParamKey::PORT => write!(f, "port"),
            SvcParamKey::IPV4HINT => write!(f, "ipv4hint"),
            SvcParamKey::ECHCONFIG => write!(f, "echconfig"),
            SvcParamKey::IPV6HINT => write!(f, "ipv6hint"),
            SvcParamKey::PRIVATE(n) => write!(f, "key{:05}", n),
            SvcParamKey::RESERVED => write!(f, "key65535"),
        }
    }
}

impl Into<u16> for SvcParamKey {
    fn into(self) -> u16 {
        match self {
            SvcParamKey::ALPN => 1,
            SvcParamKey::NODEFAULTALPN => 2,
            SvcParamKey::PORT => 3,
            SvcParamKey::IPV4HINT => 4,
            SvcParamKey::ECHCONFIG => 5,
            SvcParamKey::IPV6HINT => 6,
            SvcParamKey::PRIVATE(n) => n,
            SvcParamKey::RESERVED => 65535,
        }
    }
}

impl From<u16> for SvcParamKey {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::ALPN,
            2 => Self::NODEFAULTALPN,
            3 => Self::PORT,
            4 => Self::IPV4HINT,
            5 => Self::ECHCONFIG,
            6 => Self::IPV6HINT,
            65535 => Self::RESERVED,
            other => Self::PRIVATE(other),
        }
    }
}

impl Display for HTTPS<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\t{}.\t", self.priority(), self.target_name())?;

        for (i, next) in self.params().enumerate() {
            if i != 0 {
                write!(f, " ")?;
            }

            write!(f, "{}=", next.key())?;

            // write values
            for (j, val) in next.values().enumerate() {
                if j != 0 {
                    write!(f, ",")?;
                }
                write!(f, "{}", unsafe { std::str::from_utf8_unchecked(val) })?;
            }
        }
        Ok(())
    }
}

struct HttpsSvcParamIter<'a>(&'a [u8]);

impl<'a> Iterator for HttpsSvcParamIter<'a> {
    type Item = HttpsSvcParam<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }

        let next = HttpsSvcParam(self.0);
        self.0 = &self.0[next.len()..];

        Some(next)
    }
}

pub struct HttpsSvcParam<'a>(&'a [u8]);

impl HttpsSvcParam<'_> {
    pub fn len(&self) -> usize {
        let size = BigEndian::read_u16(&self.0[2..]) as usize;
        4 + size
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn key(&self) -> SvcParamKey {
        SvcParamKey::from(BigEndian::read_u16(self.0))
    }

    pub fn values(&self) -> impl Iterator<Item = &'_ [u8]> {
        let size = BigEndian::read_u16(&self.0[2..]) as usize;
        HttpsSvcParamValues(&self.0[4..4 + size])
    }
}

struct HttpsSvcParamValues<'a>(&'a [u8]);

impl<'a> Iterator for HttpsSvcParamValues<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let mut size = self.0[0] as usize;
        if size + 1 > self.0.len() {
            size = self.0.len() - 1;
        }

        let next = &self.0[1..size + 1];
        self.0 = &self.0[size + 1..];

        Some(next)
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct AAAA<'a>(&'a [u8]);

impl AAAA<'_> {
    pub fn ipaddr(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            BigEndian::read_u16(self.0),
            BigEndian::read_u16(&self.0[2..]),
            BigEndian::read_u16(&self.0[4..]),
            BigEndian::read_u16(&self.0[6..]),
            BigEndian::read_u16(&self.0[8..]),
            BigEndian::read_u16(&self.0[10..]),
            BigEndian::read_u16(&self.0[12..]),
            BigEndian::read_u16(&self.0[14..]),
        )
    }
}

impl<'a> Display for AAAA<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ipaddr())
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn preference(&self) -> u16 {
        BigEndian::read_u16(&self.raw[self.offset..])
    }

    pub fn mail_exchange(&self) -> Notation<'_> {
        Notation::new(&self.raw[..self.offset + self.size], 2 + self.offset)
    }
}

impl<'a> Display for MX<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.preference(), self.mail_exchange())
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
        Notation::new(self.raw, self.offset)
    }
}

impl Display for PTR<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.domain_name())
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct NS<'a> {
    raw: &'a [u8],
    offset: usize,
    size: usize,
}

impl NS<'_> {
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn nameserver(&self) -> Notation<'_> {
        Notation::new(self.raw, self.offset)
    }
}

impl Display for NS<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.nameserver())
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn cname(&self) -> Notation<'_> {
        Notation::new(self.raw, self.offset)
    }
}

impl Display for CNAME<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cname())
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn primary_nameserver(&self) -> Notation<'_> {
        Notation::new(self.raw, self.offset)
    }

    pub fn responsible_authority_mailbox(&self) -> Notation<'_> {
        Notation::new(self.raw, self.offset + self.primary_nameserver().len())
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
            "{} {} {} {} {} {} {}",
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
    if domain == "." {
        return true;
    }

    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new("^([a-z0-9_-]{1,63})(\\.[a-z0-9_-]{1,63})+\\.?$").unwrap());

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
        let notation = Notation::new(&raw[..], offset);

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

    #[test]
    fn test_broken() {
        init();

        let msg = {
            // let raw = hex::decode("d3138180000100020000000107696f73686f73740671746c63646e03636f6d0000010001c00c00010001000000140004b65bffd5c00c00010001000000140004705a287c0000290200000000000000").unwrap();
            let s = "1234818000010001000000000377777706676f6f676c6503636f6d0000410001c00c0041000100002f82000d00010000010006026832026833";
            let raw = hex::decode(s).unwrap();
            Message::from(raw)
        };

        let flags = msg.flags();
        info!("id: {}", msg.id());
        info!("is_response: {}", flags.is_response());
        info!("is_truncated: {}", flags.is_message_truncated());
        info!("is_recursive_query: {}", flags.is_recursive_query());
        info!("opcode: {:?}", flags.opcode());
        info!("questions_num: {}", msg.question_count());
        info!("answers_num: {}", msg.answer_count());

        for (i, question) in msg.questions().enumerate() {
            let name = question.name();
            info!("question#{}: name={}({}B)", i, name, name.len());
        }

        for (i, answer) in msg.answers().enumerate() {
            let name = answer.name();
            let rdata = answer.rdata().unwrap();
            let kind = answer.kind();

            info!(
                "answer#{}({}B): name={}({}B) kind={:?} rdata={}",
                i,
                answer.len(),
                name,
                name.len(),
                kind,
                rdata
            );
        }
    }
}
