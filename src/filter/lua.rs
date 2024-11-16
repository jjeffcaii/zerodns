use super::proto::Filter;
use crate::client::request as resolve;
use crate::filter::{handle_next, Context, FilterFactory, Options};
use crate::protocol::{Class, Flags, Kind, Message, DNS};
use async_trait::async_trait;
use mlua::prelude::*;
use mlua::{Function, Lua, UserData, UserDataMethods};
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use std::net::Ipv4Addr;
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
    fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
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

struct LuaJsonModule;

impl UserData for LuaJsonModule {
    fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("encode", |lua, _, value: mlua::Value| {
            let mut b = SmallVec::<[u8; 512]>::new();
            serde_json::to_writer(&mut b, &value).map_err(LuaError::external)?;
            lua.create_string(&b[..])
        });
        methods.add_method("decode", |lua, _, input: LuaString| {
            let s = input.to_str()?;
            let v = serde_json::from_str::<serde_json::Value>(s).map_err(LuaError::external)?;
            lua.to_value(&v)
        });
    }
}

#[derive(Clone)]
struct LuaMessage(Message);

impl<'lua> FromLua<'lua> for LuaMessage {
    fn from_lua(value: LuaValue<'lua>, lua: &'lua Lua) -> LuaResult<Self> {
        match value {
            LuaValue::UserData(data) => Ok(Clone::clone(&*data.borrow::<Self>()?)),
            _ => unreachable!(),
        }
    }
}

impl UserData for LuaMessage {
    fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("questions_count", |_, this, ()| Ok(this.0.question_count()));
        methods.add_method("flags", |lua, this, ()| Ok(LuaFlags(this.0.flags())));
        methods.add_method("questions", |lua, this, ()| {
            let mut questions = vec![];
            for next in this.0.questions() {
                let tbl = lua.create_table()?;
                tbl.set("name", next.name().to_string())?;
                tbl.set("kind", next.kind() as u8)?;
                tbl.set("class", next.class() as u8)?;
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

        methods.add_method("tostring", |lua, this, ()| {
            let mut b = SmallVec::<[u8; 512]>::new();
            {
                use std::io::Write;
                write!(&mut b, ";; ANSWER SECTION:").ok();

                let msg = &this.0;

                for answer in msg.answers() {
                    write!(
                        &mut b,
                        "\n{}\t{}\t{}\t{}\t{}",
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
    fn add_fields<'lua, F: LuaUserDataFields<'lua, Self>>(fields: &mut F) {
        fields.add_field_method_get("request", |lua, this| {
            let msg = LuaMessage(Clone::clone(unsafe { this.1.as_ref().unwrap() }));
            Ok(msg)
        });
    }
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("answer", |lua, this, msg: LuaMessage| {
            let resp = unsafe { this.2.as_mut().unwrap() };
            resp.replace(msg.0);
            Ok(())
        });
        methods.add_method("answer_record_a", |lua, this, ipv4: LuaString| {
            let req = unsafe { this.1.as_ref().unwrap() };
            let resp = unsafe { this.2.as_mut().unwrap() };
            let s = ipv4.to_string_lossy();
            let ipv4 = Ipv4Addr::from_str(&s)?;

            let flags = Flags::builder()
                .response()
                .recursive_query(true)
                .recursive_available(true)
                .build();

            let mut v = SmallVec::<[u8; 256]>::new();
            {
                use std::io::Write;

                if let Some(first) = req.questions().next() {
                    write!(&mut v, "{}", first.name()).ok();
                }
            }

            let name = unsafe { std::str::from_utf8_unchecked(&v[..]) };

            let octets = ipv4.octets();

            let msg = Message::builder()
                .id(req.id())
                .flags(flags)
                .answer(name, Kind::A, Class::IN, 300, &octets[..])
                .build()
                .unwrap();

            resp.replace(msg);

            Ok(())
        });
    }
}

struct LuaFlags(Flags);

impl UserData for LuaFlags {
    fn add_fields<'lua, F: LuaUserDataFields<'lua, Self>>(fields: &mut F) {
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

            let handler = globals.get::<_, Function>("handle");

            if let Ok(handler) = handler {
                lua.scope(|scope| {
                    let uctx = scope.create_userdata(LuaContext(ctx, req, res))?;
                    let _ = handler.call::<_, Option<LuaValue>>(uctx)?;
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

            // create a lua method to resolve addr:
            //
            // Method Signature:
            //   LuaMessage resolve(req,dns)
            //
            // Args Description:
            //    - req: the original dns request, see LuaMessage.
            //    - dns: a string (eg: '1.1.1.1','udp://1.1.1.1:53','tcp://1.1.1.1:53'), see DNS.
            let fn_resolve = vm.create_function(|lua, args: (LuaMessage, LuaString)| {
                let (req, dns) = args;

                let dns = DNS::from_str(&dns.to_string_lossy()).map_err(LuaError::external)?;

                // FIXME: How to call async method gracefully???
                let (tx, rx) = std::sync::mpsc::channel();
                RUNTIME.spawn(async move {
                    let v = resolve(&dns, &req.0, Duration::from_secs(15))
                        .await
                        .map(LuaMessage)
                        .map_err(LuaError::external);
                    tx.send(v).unwrap();
                });
                rx.recv().map_err(LuaError::external)?
            })?;

            // bind global modules
            {
                let globals = vm.globals();
                globals.set("resolve", fn_resolve)?;
                globals.set("json", LuaJsonModule)?;
                globals.set("logger", LuaLoggerModule)?;
            }

            vm.load(script).exec()?;

            Arc::new(Mutex::new(vm))
        };

        Ok(Self { vm })
    }
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
            local dns = '8.8.8.8'

            function handle(ctx)
              logger:info('--- begin to resolve from '..dns)
              local resp = resolve(ctx.request,dns)
              logger:info('--- resolve from '..dns..' ok: '..resp:tostring())
              ctx:answer(resp)
            end
            "#;

        let factory = {
            let mut opts = Options::default();
            opts.insert("script".into(), script.into());
            LuaFilterFactory::try_from(&opts)?
        };

        let f = factory.get()?;

        let mut ctx = Context::default();
        let mut req = {
            // type=A domain=baidu.com
            let raw = hex::decode(
                "128e0120000100000000000105626169647503636f6d00000100010000291000000000000000",
            )?;
            Message::from(raw)
        };
        let mut resp = None;

        let res = f.handle(&mut ctx, &mut req, &mut resp).await;
        assert!(res.is_ok());
        assert!(resp.is_some());

        Ok(())
    }
}
