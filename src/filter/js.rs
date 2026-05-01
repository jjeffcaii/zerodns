use super::proto::Filter;
use crate::cachestr::Cachestr;
use crate::client::request as resolve;
use crate::filter::{Context, ContextFlags, FilterFactory, Options, handle_next};
use crate::protocol::{Class, DNS, Flags, Kind, Message, OpCode, RCode, RDataOwned};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use rquickjs::{
    Context as JsContext, Ctx, FromJs, Function, JsLifetime, Object, Result as JsResult, Runtime,
    Value, class::Trace, function::This,
};
use smallvec::{SmallVec, smallvec};
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime;
use tokio::sync::Mutex;

static RUNTIME: Lazy<runtime::Runtime> = Lazy::new(|| {
    runtime::Builder::new_multi_thread()
        .name("zerodns-js-runtime")
        .enable_all()
        .build()
        .unwrap()
});

mod logger {
    pub fn debug(msg: String) {
        debug!("{}", msg);
    }
    pub fn info(msg: String) {
        info!("{}", msg);
    }
    pub fn warn(msg: String) {
        warn!("{}", msg);
    }
    pub fn error(msg: String) {
        error!("{}", msg);
    }
}

mod json {
    pub fn encode<'js>(
        ctx: rquickjs::Ctx<'js>,
        value: rquickjs::Value<'js>,
    ) -> rquickjs::Result<String> {
        let s: rquickjs::String = ctx.json_stringify(value)?.ok_or(rquickjs::Error::Unknown)?;
        s.to_string()
    }

    pub fn decode(ctx: rquickjs::Ctx<'_>, input: String) -> rquickjs::Result<rquickjs::Value<'_>> {
        ctx.json_parse(input)
    }
}

#[derive(Trace, JsLifetime)]
#[rquickjs::class]
pub struct JsFlags {
    #[qjs(skip_trace)]
    flags: Flags,
}

#[rquickjs::methods]
impl JsFlags {
    #[qjs(get)]
    pub fn opcode(&self) -> u16 {
        self.flags.opcode() as u16
    }
    #[qjs(get, rename = "responseCode")]
    pub fn response_code(&self) -> u8 {
        self.flags.response_code() as u8
    }
    #[qjs(get, rename = "authoritative")]
    pub fn is_authoritative(&self) -> bool {
        self.flags.is_authoritative()
    }
    #[qjs(get, rename = "truncated")]
    pub fn is_message_truncated(&self) -> bool {
        self.flags.is_message_truncated()
    }
    #[qjs(get, rename = "response")]
    pub fn is_response(&self) -> bool {
        self.flags.is_response()
    }
    #[qjs(get, rename = "recursionAvailable")]
    pub fn is_recursion_available(&self) -> bool {
        self.flags.is_recursion_available()
    }
    #[qjs(get, rename = "recursiveQuery")]
    pub fn is_recursive_query(&self) -> bool {
        self.flags.is_recursive_query()
    }
}

#[derive(Trace, JsLifetime, Clone)]
#[rquickjs::class]
pub struct JsMessage {
    #[qjs(skip_trace)]
    msg: Message,
}

#[rquickjs::methods]
impl JsMessage {
    pub fn id(&self) -> u16 {
        self.msg.id()
    }
    #[qjs(rename = "questionsCount")]
    pub fn questions_count(&self) -> usize {
        self.msg.question_count().into()
    }
    pub fn flags(&self) -> JsFlags {
        JsFlags {
            flags: self.msg.flags(),
        }
    }
    pub fn questions<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let arr = rquickjs::Array::new(ctx.clone())?;
        for (i, next) in self.msg.questions().enumerate() {
            let obj = Object::new(ctx.clone())?;
            obj.set("name", next.name().to_string())?;
            obj.set("class", next.class() as u8)?;
            obj.set("type", next.kind() as u8)?;
            arr.set(i, obj)?;
        }
        Ok(arr.into_value())
    }
    pub fn answers<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let arr = rquickjs::Array::new(ctx.clone())?;
        for (i, answer) in self.msg.answers().enumerate() {
            let obj = Object::new(ctx.clone())?;
            obj.set("kind", answer.kind() as u8)?;
            obj.set("name", answer.name().to_string())?;
            if let Ok(rdata) = answer.rdata() {
                obj.set("rdata", rdata.to_string())?;
            }
            arr.set(i, obj)?;
        }
        Ok(arr.into_value())
    }
    #[allow(non_snake_case)]
    pub fn toString(&self, ctx: Ctx<'_>) -> JsResult<String> {
        let mut b: SmallVec<[u8; 512]> = smallvec![];

        {
            use std::io::Write;

            let flags = self.flags().flags;

            write!(
                &mut b,
                ";; ID={:#x}, FLAGS={:#b}, RCODE={}, OPCODE={}",
                self.id(),
                flags.as_u16(),
                flags.response_code(),
                flags.opcode(),
            )
            .ok();

            write!(&mut b, "\n;; QUESTION:").ok();

            for question in self.msg.questions() {
                write!(
                    &mut b,
                    "\n{}\t{}\t{}",
                    question.name(),
                    question.class(),
                    question.kind()
                )
                .ok();
            }

            write!(&mut b, "\n;; ANSWER:").ok();

            for answer in self.msg.answers() {
                write!(
                    &mut b,
                    "\n{}.\t{}\t{}\t{}\t{}",
                    answer.name(),
                    answer.time_to_live(),
                    answer.class(),
                    answer.kind(),
                    answer
                        .rdata()
                        .map_err(|e| rquickjs::Error::new_loading_message(
                            "Message",
                            e.to_string()
                        ))?,
                )
                .ok();
            }

            Ok(unsafe { String::from_utf8_unchecked(b.to_vec()) })
        }
    }
}

#[derive(Trace, JsLifetime)]
#[rquickjs::class(rename = "Message")]
pub struct JsMessageBuilder {
    id: u16,
    #[qjs(skip_trace)]
    flags: Flags,
    #[qjs(skip_trace)]
    questions: SmallVec<[(Cachestr, Class, Kind); 1]>,
    #[qjs(skip_trace)]
    answers: SmallVec<[(Cachestr, Class, Kind, u32, RDataOwned); 1]>,
}

#[rquickjs::methods]
impl JsMessageBuilder {
    #[qjs(constructor)]
    pub fn new(id: u16, opts: rquickjs::function::Opt<Object<'_>>) -> JsResult<Self> {
        let mut is_request = false;
        let mut recursive_query = true;
        let mut recursive_available = true;
        let mut truncated = false;
        let mut authoritative = false;
        let mut rcode = RCode::NoError;
        let mut opcode = OpCode::StandardQuery;

        if let Some(opts) = opts.0 {
            is_request = opts.get::<_, bool>("request").unwrap_or_default();
            if let Ok(v) = opts.get::<_, bool>("recursive_query") {
                recursive_query = v;
            }
            if let Ok(v) = opts.get::<_, bool>("recursive_available") {
                recursive_available = v;
            }
            if let Ok(v) = opts.get::<_, bool>("truncated") {
                truncated = v;
            }
            if let Ok(v) = opts.get::<_, bool>("authoritative") {
                authoritative = v;
            }
            if let Ok(v) = opts.get::<_, u16>("rcode") {
                rcode = RCode::try_from(v).map_err(|_| {
                    rquickjs::Error::new_loading_message("Message", format!("invalid rcode {}", v))
                })?;
            }
            if let Ok(v) = opts.get::<_, u16>("opcode") {
                opcode = OpCode::try_from(v).map_err(|_| {
                    rquickjs::Error::new_loading_message("Message", format!("invalid opcode {}", v))
                })?;
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

        Ok(JsMessageBuilder {
            id,
            flags,
            questions: Default::default(),
            answers: Default::default(),
        })
    }

    #[qjs(get)]
    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn question<'js>(
        This(this): This<rquickjs::Class<'js, Self>>,
        name: String,
        class: Value<'js>,
        typ: Value<'js>,
    ) -> JsResult<rquickjs::Class<'js, Self>> {
        let class = parse_class(class)?;
        let kind = parse_kind(typ)?;
        {
            let mut borrow = this.borrow_mut();
            borrow.questions.push((Cachestr::from(&*name), class, kind));
        }
        Ok(this)
    }

    pub fn answer<'js>(
        This(this): This<rquickjs::Class<'js, Self>>,
        name: String,
        ttl: u32,
        class: Value<'js>,
        typ: Value<'js>,
        data: Value<'js>,
    ) -> JsResult<rquickjs::Class<'js, Self>> {
        let class = parse_class(class.clone())?;
        let typ = parse_kind(typ.clone())?;

        let rdata: JsResult<RDataOwned> = match typ {
            Kind::A => {
                let s: String = FromJs::from_js(data.ctx(), data.clone())?;
                let v = s
                    .parse::<Ipv4Addr>()
                    .map_err(|e| rquickjs::Error::new_loading_message("Message", e.to_string()))?;
                Ok(RDataOwned::A(v))
            }
            Kind::AAAA => {
                let s: String = FromJs::from_js(data.ctx(), data.clone())?;
                let v = s
                    .parse::<Ipv6Addr>()
                    .map_err(|e| rquickjs::Error::new_loading_message("Message", e.to_string()))?;
                Ok(RDataOwned::AAAA(v))
            }
            Kind::MX => {
                let obj = data.into_object().ok_or_else(|| {
                    rquickjs::Error::new_loading_message("Message", "expect object for MX")
                })?;
                let preference: u16 = obj.get("preference")?;
                let mail_exchange: String = obj.get("mail_exchange")?;
                Ok(RDataOwned::MX {
                    preference,
                    mail_exchange: Cachestr::from(&*mail_exchange),
                })
            }
            Kind::CNAME => {
                let s: String = FromJs::from_js(data.ctx(), data.clone())?;
                Ok(RDataOwned::CNAME(Cachestr::from(&*s)))
            }
            other => Err(rquickjs::Error::new_loading_message(
                "Message",
                format!("type '{}' is not supported yet", other),
            )),
        };
        {
            let mut borrow = this.borrow_mut();
            borrow
                .answers
                .push((Cachestr::from(&*name), class, typ, ttl, rdata?));
        }
        Ok(this)
    }

    pub fn build(&self) -> JsResult<JsMessage> {
        let mut bu = Message::builder().id(self.id).flags(self.flags);
        for (name, class, kind) in &self.questions {
            bu = bu.question(Cow::from(name.as_ref()), *kind, *class);
        }
        for (name, class, typ, ttl, data) in &self.answers {
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
        bu.build()
            .map(|msg| JsMessage { msg })
            .map_err(|e| rquickjs::Error::new_loading_message("JsMessageBuilder", e.to_string()))
    }
}

#[derive(Trace, JsLifetime)]
#[rquickjs::class(rename = "Resolver")]
pub struct JsResolver {
    #[qjs(skip_trace)]
    dns: SmallVec<[DNS; 1]>,
}

#[rquickjs::methods]
impl JsResolver {
    #[qjs(constructor)]
    pub fn new(args: rquickjs::function::Rest<String>) -> JsResult<Self> {
        let mut v = SmallVec::<[DNS; 1]>::new();
        for arg in args.0 {
            let dns = DNS::from_str(&arg)
                .map_err(|e| rquickjs::Error::new_loading_message("Resolver", e.to_string()))?;
            v.push(dns);
        }
        Ok(JsResolver { dns: v })
    }

    pub fn resolve(
        &self,
        request: JsMessage,
        timeout: rquickjs::function::Opt<u64>,
    ) -> JsResult<JsMessage> {
        let req = request.msg;
        let dns = self.dns.clone();
        let timeout = {
            let mut t = Duration::from_secs(15);
            if let Some(n) = timeout.0 {
                if n > 0 {
                    t = Duration::from_secs(n);
                }
            }
            t
        };

        let (tx, rx) = std::sync::mpsc::channel();
        RUNTIME.spawn(async move {
            let mut last: anyhow::Result<Message> = Err(crate::Error::ResolveNothing.into());
            for next in &dns {
                last = resolve(next, &req, timeout).await;
                if last.is_ok() {
                    break;
                }
            }
            tx.send(last.map(|msg| JsMessage { msg })).unwrap();
        });
        rx.recv()
            .map_err(|e| rquickjs::Error::new_loading_message("Resolver", e.to_string()))?
            .map_err(|e| rquickjs::Error::new_loading_message("Resolver", e.to_string()))
    }

    #[allow(non_snake_case)]
    pub fn toString(&self) -> String {
        let mut b = SmallVec::<[u8; 32]>::new();
        let mut iter = self.dns.iter();
        b.push(b'[');
        use std::io::Write;
        if let Some(first) = iter.next() {
            write!(&mut b, "{}", first).ok();
        }
        for next in iter {
            write!(&mut b, ",{}", next).ok();
        }
        b.push(b']');
        unsafe { String::from_utf8_unchecked(b.to_vec()) }
    }
}

#[derive(Clone, Copy, Default)]
pub struct JsCtxPtr {
    pub ctx_ptr: *mut Context,
    pub req_ptr: *mut Message,
    pub res_ptr: *mut Option<Message>,
}

unsafe impl Send for JsCtxPtr {}
unsafe impl Sync for JsCtxPtr {}

#[derive(Trace, JsLifetime)]
#[rquickjs::class]
pub struct JsContextWrapper {
    #[qjs(skip_trace)]
    pub inner: JsCtxPtr,
}

impl JsContextWrapper {
    pub fn new(inner: JsCtxPtr) -> Self {
        Self { inner }
    }
}

#[rquickjs::methods]
impl JsContextWrapper {
    #[qjs(get)]
    pub fn request(&self) -> JsMessage {
        JsMessage {
            msg: unsafe { (*self.inner.req_ptr).clone() },
        }
    }

    #[qjs(get)]
    pub fn peer(&self) -> String {
        let ctx = unsafe { &*self.inner.ctx_ptr };
        ctx.client_addr().to_string()
    }

    pub fn nocache(&self) {
        let ctx = unsafe { &mut *self.inner.ctx_ptr };
        ctx.flags.set(ContextFlags::NO_CACHE, true);
    }

    pub fn answer(&self, msg: JsMessage) {
        let res = unsafe { &mut *self.inner.res_ptr };
        res.replace(msg.msg);
    }
}

impl<'js> rquickjs::class::Trace<'js> for JsCtxPtr {
    fn trace<'a>(&self, _tracer: rquickjs::class::Tracer<'a, 'js>) {}
}
unsafe impl<'js> rquickjs::JsLifetime<'js> for JsCtxPtr {
    type Changed<'to> = JsCtxPtr;
}

fn parse_class(v: Value<'_>) -> JsResult<Class> {
    if let Some(s) = v.as_string() {
        let s = s.to_string()?;
        return s
            .parse::<Class>()
            .map_err(|e| rquickjs::Error::new_loading_message("parse_class", e.to_string()));
    }
    if let Some(n) = v.as_int() {
        if n >= 0 && n <= u16::MAX as i32 {
            if let Ok(class) = Class::try_from(n as u16) {
                return Ok(class);
            }
        }
    }
    Err(rquickjs::Error::new_loading_message(
        "parse_class",
        "invalid class",
    ))
}

fn parse_kind(v: Value<'_>) -> JsResult<Kind> {
    if let Some(s) = v.as_string() {
        let s = s.to_string()?;
        return s
            .parse::<Kind>()
            .map_err(|e| rquickjs::Error::new_loading_message("parse_kind", e.to_string()));
    }
    if let Some(n) = v.as_int() {
        if n >= 0 && n <= u16::MAX as i32 {
            if let Ok(kind) = Kind::try_from(n as u16) {
                return Ok(kind);
            }
        }
    }
    Err(rquickjs::Error::new_loading_message(
        "parse_kind",
        "invalid type",
    ))
}

pub struct JSFilter {
    next: Option<Box<dyn Filter>>,
    vm: Arc<Mutex<JsContext>>,
}

#[async_trait]
impl Filter for JSFilter {
    async fn handle(
        &self,
        ctx: &mut Context,
        req: &mut Message,
        res: &mut Option<Message>,
    ) -> crate::Result<()> {
        let js_ctx_ptr = JsCtxPtr {
            ctx_ptr: ctx,
            req_ptr: req,
            res_ptr: res,
        };

        let handle_res = {
            let js_ctx = self.vm.lock().await;
            js_ctx.with(|ctx| {
                let globals = ctx.globals();
                let handler: Function = globals
                    .get("handle")
                    .map_err(|_| anyhow!("handle function not found"))?;
                if let Err(e) = handler.call::<(rquickjs::Class<'_, JsContextWrapper>,), ()>((
                    rquickjs::Class::instance(ctx.clone(), JsContextWrapper::new(js_ctx_ptr))?,
                )) {
                    let err_msg = if let Some(exception) = ctx.catch().into_exception() {
                        format!(
                            "JS Exception in handle: {:?} at {:?}",
                            exception.message(),
                            exception.stack()
                        )
                    } else {
                        format!("JS Error in handle: {:?}", e)
                    };
                    error!("{}", err_msg);
                    return Err(anyhow!("{}", err_msg));
                }
                Ok::<_, anyhow::Error>(())
            })
        };

        if let Err(e) = handle_res {
            error!("JS handle failed: {:?}", e);
            return Err(e);
        }

        handle_next(self.next.as_deref(), ctx, req, res).await
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

pub struct JSFilterFactory {
    vm: Arc<Mutex<JsContext>>,
}

impl FilterFactory for JSFilterFactory {
    type Item = JSFilter;

    fn get(&self) -> crate::Result<Self::Item> {
        Ok(JSFilter {
            next: None,
            vm: self.vm.clone(),
        })
    }
}

impl TryFrom<&Options> for JSFilterFactory {
    type Error = anyhow::Error;

    fn try_from(value: &Options) -> Result<Self, Self::Error> {
        let val = value
            .get("script")
            .ok_or_else(|| anyhow!("script not found"))?;
        let script = val.as_str().ok_or_else(|| anyhow!("script not a string"))?;

        let runtime = Runtime::new()?;
        let context = JsContext::full(&runtime)?;

        context.with(|ctx| {
            let globals = ctx.globals();

            // Register logger
            let logger_obj = Object::new(ctx.clone())?;
            logger_obj.set("debug", Function::new(ctx.clone(), logger::debug)?)?;
            logger_obj.set("info", Function::new(ctx.clone(), logger::info)?)?;
            logger_obj.set("warn", Function::new(ctx.clone(), logger::warn)?)?;
            logger_obj.set("error", Function::new(ctx.clone(), logger::error)?)?;
            globals.set("logger", logger_obj)?;

            // Register json
            let json_obj = Object::new(ctx.clone())?;
            json_obj.set("encode", Function::new(ctx.clone(), json::encode)?)?;
            json_obj.set("decode", Function::new(ctx.clone(), json::decode)?)?;
            globals.set("json", json_obj)?;

            // Define classes
            rquickjs::Class::<JsFlags>::define(&globals)?;
            rquickjs::Class::<JsMessage>::define(&globals)?;
            rquickjs::Class::<JsMessageBuilder>::define(&globals)?;
            rquickjs::Class::<JsResolver>::define(&globals)?;
            rquickjs::Class::<JsContextWrapper>::define(&globals)?;

            // Eval script
            if let Err(e) = ctx.eval::<(), _>(script) {
                let err_msg = if let Some(exception) = ctx.catch().into_exception() {
                    format!(
                        "JS Exception: {:?} at {:?}",
                        exception.message(),
                        exception.stack()
                    )
                } else {
                    format!("JS Error: {:?}", e)
                };
                error!("{}", err_msg);
                return Err(anyhow!("{}", err_msg));
            }
            Ok::<_, anyhow::Error>(())
        })?;

        Ok(JSFilterFactory {
            vm: Arc::new(Mutex::new(context)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        pretty_env_logger::try_init_timed().ok();
    }

    #[tokio_shared_rt::test(shared)]
    async fn test_js() -> anyhow::Result<()> {
        init();

        let script = r#"
            const resolver = new Resolver('208.67.222.222', '208.67.220.220');

            function handle(ctx) {
              logger.info('--- begin to resolve from ' + resolver.toString());
              const resp = resolver.resolve(ctx.request);
              logger.info('--- resolve from ' + resolver.toString() + ':\n' + resp.toString());

              const msg = new Message(resp.id())
                .question('dns.google', 'IN', 'A')
                .answer('dns.google', 123, 'IN', 'A', '8.8.8.8')
                .answer('dns.google', 123, 'IN', 'A', '8.8.4.4')
                .build();
              
              ctx.answer(msg);
            }
        "#;

        let factory = {
            let mut opts = Options::default();
            opts.insert("script".into(), script.into());
            JSFilterFactory::try_from(&opts)?
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
