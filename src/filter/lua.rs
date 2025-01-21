use super::proto::Filter;
use crate::cachestr::Cachestr;
use crate::client::request as resolve;
use crate::filter::{handle_next, Context, ContextFlags, FilterFactory, Options};
use crate::protocol::{Class, Flags, Kind, Message, OpCode, RCode, RDataOwned, DNS};
use async_trait::async_trait;
use mlua::prelude::*;
use mlua::{Function, Lua, MetaMethod, UserData, Variadic};
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime;
use tokio::sync::Mutex;

static RUNTIME: Lazy<runtime::Runtime> = Lazy::new(|| {
    runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

struct LuaLoggerModule;

impl UserData for LuaLoggerModule {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("debug", |_lua, _this, msg: LuaString| {
            debug!("{}", msg.to_string_lossy());
            Ok(())
        });
        methods.add_method("info", |_, _this, msg: LuaString| {
            info!("{}", msg.to_string_lossy());
            Ok(())
        });
        methods.add_method("warn", |_lua, _this, msg: LuaString| {
            warn!("{}", msg.to_string_lossy());
            Ok(())
        });
        methods.add_method("error", |_lua, _this, msg: LuaString| {
            error!("{}", msg.to_string_lossy());
            Ok(())
        });
    }
}

#[derive(Debug, Default)]
struct LuaMessageBuilder {
    id: u16,
    flags: Flags,
    questions: SmallVec<[(Cachestr, Class, Kind); 1]>,
    answers: SmallVec<[(Cachestr, Class, Kind, u32, RDataOwned); 1]>,
}

impl UserData for LuaMessageBuilder {
    fn add_fields<F: LuaUserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("id", |_lua, this| Ok(this.id));
    }

    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method_mut(
            "question",
            |_lua, this, (name, class, typ): (LuaString, LuaValue, LuaValue)| {
                let class = parse_class(class)?;
                let kind = parse_kind(typ)?;

                let s = name.to_str()?;
                this.questions.push((Cachestr::from(&*s), class, kind));
                Ok(())
            },
        );

        methods.add_method_mut("answer", |_lua, this, (name, ttl, class, typ, data): (LuaString, u32, LuaValue, LuaValue, LuaValue)| {
            let name = name.to_str()?;

            let class = parse_class(class)?;
            let typ = parse_kind(typ)?;

            let to_str = || {
                data.as_str().ok_or_else(|| LuaError::external(anyhow!("incorrect data type '{}', expect is 'string'",data.type_name())))
            };
            let to_table = || {
                data.as_table().ok_or_else(|| LuaError::external(anyhow!("incorrect data type '{}', expect is 'table'",data.type_name())))
            };

            let rdata: LuaResult<RDataOwned> = match typ {
                Kind::A => {
                    let s = to_str()?;
                    let v = s.parse::<Ipv4Addr>()?;
                    Ok(RDataOwned::A(v))
                }
                Kind::AAAA => {
                    let s = to_str()?;
                    let v = s.parse::<Ipv6Addr>()?;
                    Ok(RDataOwned::AAAA(v))
                }
                Kind::MX => {
                    let tbl = to_table()?;
                    let preference = tbl.get::<u16>("preference")?;
                    let mail_exchange = tbl.get::<LuaString>("mail_exchange")?;
                    let mail_exchange_str = mail_exchange.to_str()?;

                    Ok(RDataOwned::MX {
                        preference,
                        mail_exchange: Cachestr::from(&*mail_exchange_str),
                    })
                }
                Kind::CNAME => {
                    let s = to_str()?;
                    Ok(RDataOwned::CNAME(Cachestr::from(&*s)))
                }
                other => Err(LuaError::external(anyhow!("type '{}' is not supported yet", other))),
            };
            this.answers.push((Cachestr::from(&*name), class, typ, ttl, rdata?));

            Ok(())
        });

        methods.add_method("build", |_lua, this, ()| {
            let mut bu = Message::builder().id(this.id).flags(this.flags);

            for (name, class, kind) in &this.questions {
                bu = bu.question(Cow::from(name.as_ref()), *kind, *class);
            }

            for (name, class, typ, ttl, data) in &this.answers {
                let name = Cow::from(name.as_ref());
                match data {
                    RDataOwned::A(ipv4) => {
                        let octets = ipv4.octets().to_vec();
                        bu = bu.answer(name, *typ, *class, *ttl, Cow::Owned(octets));
                    }
                    RDataOwned::AAAA(ipv6) => {
                        let octets = ipv6.octets().to_vec();
                        bu = bu.answer(name, *typ, *class, *ttl, Cow::Owned(octets));
                    }
                    RDataOwned::CNAME(cname) => {
                        bu = bu.answer(name, *typ, *class, *ttl, cname.as_bytes());
                    }
                    RDataOwned::TXT(txt) => {
                        let b = txt.as_bytes();
                        let mut buf = Vec::with_capacity(b.len() + 1);
                        buf.push(b.len() as u8);
                        buf.extend_from_slice(b);
                        bu = bu.answer(name, *typ, *class, *ttl, Cow::Owned(buf));
                    }
                    RDataOwned::UNKNOWN(b) => {
                        bu = bu.answer(name, *typ, *class, *ttl, &b[..]);
                    }
                    _ => todo!(),
                }
            }

            bu.build().map(LuaMessage).map_err(LuaError::external)
        });
    }
}

#[derive(Debug)]
struct LuaResolver(SmallVec<[DNS; 1]>);

impl UserData for LuaResolver {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::ToString, |lua, this, ()| {
            let mut b = SmallVec::<[u8; 32]>::new();
            let mut iter = this.0.iter();
            b.push(b'[');

            use std::io::Write;

            if let Some(first) = iter.next() {
                write!(&mut b, "{}", first)?;
            }

            for next in iter {
                write!(&mut b, ",{}", next)?;
            }
            b.push(b']');

            lua.create_string(unsafe { std::str::from_utf8_unchecked(&b[..]) })
        });

        // create a lua method to resolve addr:
        //
        // Method Signature:
        //   LuaMessage resolve(req [,timeout])
        //
        // Args Description:
        //    - req: the original dns request, see LuaMessage.
        //    - dns: a string (eg: '1.1.1.1','udp://1.1.1.1:53','tcp://1.1.1.1:53'), see DNS.
        methods.add_method(
            "resolve",
            |lua, this, (request, timeout): (LuaMessage, Option<u64>)| {
                let req = Clone::clone(&request.0);
                let dns = Clone::clone(&this.0);
                let timeout = {
                    let mut t = Duration::from_secs(15);

                    if let Some(n) = timeout {
                        if n > 0 {
                            t = Duration::from_secs(n);
                        }
                    }
                    t
                };

                // FIXME: How to call async method gracefully???
                let (tx, rx) = std::sync::mpsc::channel();
                RUNTIME.spawn(async move {
                    let mut last: LuaResult<Message> =
                        Err(LuaError::external(crate::Error::ResolveNothing));
                    for next in &dns {
                        last = resolve(next, &req, timeout)
                            .await
                            .map_err(LuaError::external);
                        if last.is_ok() {
                            break;
                        }
                    }
                    tx.send(last.map(LuaMessage)).unwrap();
                });
                rx.recv().map_err(LuaError::external)?
            },
        );
    }
}

struct LuaJsonModule;

impl UserData for LuaJsonModule {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("encode", |lua, _, value: mlua::Value| {
            let mut b = SmallVec::<[u8; 512]>::new();
            serde_json::to_writer(&mut b, &value).map_err(LuaError::external)?;
            lua.create_string(&b[..])
        });
        methods.add_method("decode", |lua, _, input: LuaString| {
            let s = input.to_str()?;
            let v = serde_json::from_str::<serde_json::Value>(&s).map_err(LuaError::external)?;
            lua.to_value(&v)
        });
    }
}

#[derive(Clone)]
struct LuaMessage(Message);

impl FromLua for LuaMessage {
    fn from_lua(value: LuaValue, lua: &Lua) -> LuaResult<Self> {
        match value {
            LuaValue::UserData(data) => Ok(Clone::clone(&*data.borrow::<Self>()?)),
            _ => unreachable!(),
        }
    }
}

impl UserData for LuaMessage {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("id", |_, this, ()| Ok(this.0.id()));
        methods.add_method("questions_count", |_, this, ()| Ok(this.0.question_count()));
        methods.add_method("flags", |lua, this, ()| Ok(LuaFlags(this.0.flags())));
        methods.add_method("questions", |lua, this, ()| {
            let mut questions = vec![];
            for next in this.0.questions() {
                let tbl = lua.create_table()?;
                tbl.set("name", next.name().to_string())?;
                tbl.set("class", next.class() as u8)?;
                tbl.set("type", next.kind() as u8)?;
                questions.push(tbl);
            }
            Ok(questions)
        });

        methods.add_method("answers", |lua, this, ()| {
            let mut ret = vec![];
            for answer in this.0.answers() {
                let ans = lua.create_table()?;
                ans.set("kind", answer.kind() as u8)?;
                ans.set("name", answer.name().to_string())?;
                if let Ok(rdata) = answer.rdata() {
                    ans.set("rdata", rdata.to_string())?;
                }

                ret.push(ans);
            }
            Ok(ret)
        });

        methods.add_meta_method(MetaMethod::ToString, |lua, this, ()| {
            let mut b = SmallVec::<[u8; 512]>::new();
            {
                use std::io::Write;
                write!(&mut b, ";; ANSWER SECTION:").ok();

                let msg = &this.0;

                for answer in msg.answers() {
                    write!(
                        &mut b,
                        "\n{}.\t{}\t{}\t{}\t{}",
                        answer.name(),
                        answer.time_to_live(),
                        answer.class(),
                        answer.kind(),
                        answer
                            .rdata()
                            .map(|rdata| rdata.to_string())
                            .unwrap_or_default(),
                    )
                    .ok();
                }
            }

            let s = unsafe { std::str::from_utf8_unchecked(&b[..]) };
            s.into_lua(lua)
        });
    }
}

struct LuaContext(*mut Context, *mut Message, *mut Option<Message>);

impl UserData for LuaContext {
    fn add_fields<F: LuaUserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("request", |lua, this| {
            let msg = LuaMessage(Clone::clone(unsafe { this.1.as_ref().unwrap() }));
            Ok(msg)
        });
    }

    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("nocache", |_lua, this, ()| {
            let ctx = unsafe { this.0.as_mut().unwrap() };
            ctx.flags.set(ContextFlags::NO_CACHE, true);
            Ok(())
        });

        methods.add_method("answer", |lua, this, msg: LuaMessage| {
            let resp = unsafe { this.2.as_mut().unwrap() };
            resp.replace(msg.0);
            Ok(())
        });
    }
}

struct LuaFlags(Flags);

impl UserData for LuaFlags {
    fn add_fields<F: LuaUserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("opcode", |_lua, this| Ok(this.0.opcode() as u16));
        fields.add_field_method_get("response_code", |_lua, this| {
            Ok(this.0.response_code() as u8)
        });
        fields.add_field_method_get("is_authoritative", |_lua, this| {
            Ok(this.0.is_authoritative())
        });
        fields.add_field_method_get("is_message_truncated", |_lua, this| {
            Ok(this.0.is_message_truncated())
        });
        fields.add_field_method_get("is_response", |_lua, this| Ok(this.0.is_response()));
        fields.add_field_method_get("is_recursion_available", |_lua, this| {
            Ok(this.0.is_recursion_available())
        });
        fields.add_field_method_get("is_recursive_query", |_lua, this| {
            Ok(this.0.is_recursive_query())
        });
    }
}

pub(crate) struct LuaFilter {
    next: Option<Box<dyn Filter>>,
    vm: Arc<Mutex<Lua>>,
}

#[async_trait]
impl Filter for LuaFilter {
    async fn handle(
        &self,
        ctx: &mut Context,
        req: &mut Message,
        res: &mut Option<Message>,
    ) -> crate::Result<()> {
        {
            let lua = self.vm.lock().await;
            let globals = lua.globals();

            let handler = globals.get::<Function>("handle");

            if let Ok(handler) = handler {
                lua.scope(|scope| {
                    let uctx = scope.create_userdata(LuaContext(ctx, req, res))?;
                    let _ = handler.call::<Option<LuaValue>>(uctx)?;
                    Ok(())
                })?;
            }
        }

        handle_next(self.next.as_deref(), ctx, req, res).await
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

pub(crate) struct LuaFilterFactory {
    vm: Arc<Mutex<Lua>>,
}

impl FilterFactory for LuaFilterFactory {
    type Item = LuaFilter;

    fn get(&self) -> crate::Result<Self::Item> {
        Ok(LuaFilter {
            next: None,
            vm: Clone::clone(&self.vm),
        })
    }
}

impl TryFrom<&Options> for LuaFilterFactory {
    type Error = anyhow::Error;

    fn try_from(value: &Options) -> Result<Self, Self::Error> {
        let val = value
            .get("script")
            .ok_or_else(|| anyhow!("script not found"))?;
        let script = val.as_str().ok_or_else(|| anyhow!("script not a string"))?;

        let vm = {
            let vm = unsafe { Lua::unsafe_new() };

            // bind global modules
            {
                let globals = vm.globals();
                globals.set("json", LuaJsonModule)?;
                globals.set("logger", LuaLoggerModule)?;

                // register Message:
                // Message(id [, opts])
                // fields of opts table:
                // - request: bool, true if target is request
                // - recursive_query: bool
                // - recursive_available: bool
                // - truncated: bool
                // - authoritative: bool
                // - rcode:u16, see RCode
                // - opcode: u16, see OpCode

                globals.set(
                    "Message",
                    vm.create_function(|_, (id, opts): (u16, Option<LuaTable>)| {
                        let mut is_request = false;
                        let mut recursive_query = true;
                        let mut recursive_available = true;
                        let mut truncated = false;
                        let mut authoritative = false;
                        let mut rcode = RCode::NoError;
                        let mut opcode = OpCode::StandardQuery;

                        if let Some(opts) = opts {
                            is_request = opts.get::<bool>("request").unwrap_or_default();

                            if let Ok(v) = opts.get::<bool>("recursive_query") {
                                recursive_query = v;
                            }
                            if let Ok(v) = opts.get::<bool>("recursive_available") {
                                recursive_available = v;
                            }

                            if let Ok(v) = opts.get::<bool>("truncated") {
                                truncated = v;
                            }

                            if let Ok(v) = opts.get::<bool>("authoritative") {
                                authoritative = v;
                            }

                            if let Ok(v) = opts.get::<u16>("rcode") {
                                rcode = RCode::try_from(v)
                                    .map_err(|_| anyhow!("invalid rcode {}", v))?;
                            }

                            if let Ok(v) = opts.get::<u16>("opcode") {
                                opcode = OpCode::try_from(v)
                                    .map_err(|_| anyhow!("invalid opcode {}", v))?;
                            }
                        }

                        let flags = if is_request {
                            Flags::builder().request()
                        } else {
                            Flags::builder().response()
                        }
                        .opcode(opcode)
                        .rcode(rcode)
                        .authoritative(authoritative)
                        .recursive_query(recursive_query)
                        .recursive_available(recursive_available)
                        .truncated(truncated)
                        .build();

                        Ok(LuaMessageBuilder {
                            id,
                            flags,
                            questions: Default::default(),
                            answers: Default::default(),
                        })
                    })?,
                )?;

                // register Resolver:
                globals.set(
                    "Resolver",
                    vm.create_function(|_, (dns, rest): (LuaString, Variadic<LuaString>)| {
                        let mut v = SmallVec::<[DNS; 1]>::new();

                        let dns = {
                            let s = dns.to_str()?;
                            DNS::from_str(&s).map_err(LuaError::external)?
                        };

                        v.push(dns);

                        for next in rest {
                            let s = next.to_str()?;
                            let dns = DNS::from_str(&s).map_err(LuaError::external)?;
                            v.push(dns);
                        }

                        Ok(LuaResolver(v))
                    })?,
                )?;
            }

            vm.load(script).exec()?;

            Arc::new(Mutex::new(vm))
        };

        Ok(Self { vm })
    }
}

fn parse_class(v: LuaValue) -> LuaResult<Class> {
    if let Some(s) = v.as_str() {
        let class = s.parse::<Class>()?;
        return Ok(class);
    }

    if let Some(n) = v.as_u32() {
        if n < u16::MAX as u32 {
            if let Ok(class) = Class::try_from(n as u16) {
                return Ok(class);
            }
        }
    }

    Err(LuaError::external(anyhow!("invalid class: {:?}", v)))
}

fn parse_kind(v: LuaValue) -> LuaResult<Kind> {
    if let Some(s) = v.as_str() {
        let kind = s.parse::<Kind>()?;
        return Ok(kind);
    }

    if let Some(n) = v.as_u32() {
        if n < u16::MAX as u32 {
            if let Ok(kind) = Kind::try_from(n as u16) {
                return Ok(kind);
            }
        }
    }

    Err(LuaError::external(anyhow!("invalid type {:?}", v)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio::test]
    async fn test_lua() -> anyhow::Result<()> {
        init();

        let script = r#"
            local resolver = Resolver('208.67.222.222', '208.67.220.220')

            function handle(ctx)
              logger:info('--- begin to resolve from '..tostring(resolver))
              local resp = resolver:resolve(ctx.request)
              logger:info('--- resolve from '..tostring(resolver)..':\n'..tostring(resp))

              local msg = Message(resp:id())
              msg:question('dns.google', 'IN', 'A')
              msg:answer('dns.google', 123, 'IN', 'A', '8.8.8.8')
              msg:answer('dns.google', 123, 'IN', 'A', '8.8.4.4')
              msg:build()

              ctx:answer(msg:build())
            end
            "#;

        let factory = {
            let mut opts = Options::default();
            opts.insert("script".into(), script.into());
            LuaFilterFactory::try_from(&opts)?
        };

        let f = factory.get()?;

        let mut ctx = Context::default();
        let mut req = Message::builder()
            .id(0x1314)
            .flags(Flags::request())
            .question("dns.google", Kind::A, Class::IN)
            .build()?;

        let mut resp = None;

        let res = f.handle(&mut ctx, &mut req, &mut resp).await;
        assert!(res.is_ok());
        assert!(resp.is_some());

        if let Some(resp) = resp {
            info!(
                ";; ID={:#x}, FLAGS={:#b}, RCODE={}, OPCODE={}",
                resp.id(),
                resp.flags().as_u16(),
                resp.flags().response_code(),
                resp.flags().opcode()
            );

            info!(";; QUESTION:");
            for question in resp.questions() {
                info!(
                    "{}\t{}\t{}",
                    question.name(),
                    question.class(),
                    question.kind()
                );
            }
            info!(";; ANSWER");
            for answer in resp.answers() {
                info!(
                    "{}.\t{}\t{}\t{}\t{}",
                    answer.name(),
                    answer.time_to_live(),
                    answer.class(),
                    answer.kind(),
                    answer.rdata()?
                );
            }
        }

        Ok(())
    }
}
