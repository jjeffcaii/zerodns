use crate::cache::{CacheStore, CacheStoreExt};
use crate::error::Error;
use crate::filter::{Context, ContextFlags};
use crate::handler::Handler;
use crate::protocol::{Flags, Message, RCode};
use crate::{Error as ZError, Result};
use std::sync::Arc;

fn validate_request(req: &Message) -> Result<()> {
    for question in req.questions() {
        for next in question.name() {
            if next.is_empty() {
                continue;
            }
            let ok = next
                .iter()
                .all(|b| matches!(*b, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'-' | b'_'));
            if !ok {
                let fullname = question.name().to_string();
                bail!(ZError::InvalidRequestFormat(fullname.into()));
            }
        }
    }

    Ok(())
}

fn convert_error_to_message(
    request: &Message,
    err: anyhow::Error,
    attach_questions: bool,
) -> Message {
    let rid = request.id();
    let rflags = request.flags();

    let mut rcode = RCode::ServerFailure;

    if let Some(ze) = err.downcast_ref::<ZError>() {
        match ze {
            Error::InvalidRequestFormat(_) => rcode = RCode::NameError,
            Error::ResolveNothing => rcode = RCode::NoError,
            _ => (),
        }
    }

    // log those internal server failure:
    match rcode {
        RCode::ServerFailure => match request.questions().next() {
            Some(question) => {
                let name = question.name();
                error!("failed to handle dns request {}: {:?}", name, err);
            }
            None => error!("failed to handle dns request: {:?}", err),
        },
        RCode::NameError => match request.questions().next() {
            Some(question) => {
                let name = question.name();
                warn!("failed to handle dns request {}: {:?}", name, err);
            }
            None => warn!("failed to handle dns request: {:?}", err),
        },
        _ => (),
    }

    let flags = {
        let mut bu = Flags::builder()
            .response()
            .opcode(rflags.opcode())
            .rcode(RCode::NoError);
        if rflags.is_recursive_query() {
            bu = bu.recursive_query(true);
            bu = bu.recursive_available(true);
        }
        bu.build()
    };

    let mut bu = Message::builder().id(rid).flags(flags);

    if attach_questions {
        for next in request.questions() {
            bu = bu.raw_question(next);
        }
    }

    bu.build().unwrap()
}

pub(super) async fn handle<H, C>(
    mut req: Message,
    h: Arc<H>,
    cache: Option<Arc<C>>,
) -> (Message, bool)
where
    H: Handler,
    C: CacheStore,
{
    if let Err(e) = validate_request(&req) {
        return (convert_error_to_message(&req, e, false), false);
    }

    if let Some(cache) = cache.as_deref() {
        let id = req.id();
        req.set_id(0);
        let cached = cache.get_fixed(&req).await;
        req.set_id(id);

        if let Some(mut exist) = cached {
            exist.set_id(id);
            return (exist, true);
        }
    }

    let mut ctx = Context::default();

    match h.handle(&mut ctx, &mut req).await {
        Ok(result) => {
            let mut cached = true;
            let msg = result.unwrap_or_else(|| {
                cached = false;
                convert_error_to_message(&req, anyhow!(ZError::ResolveNothing), true)
            });

            if ctx.flags.contains(ContextFlags::NO_CACHE) {
                cached = false;
            }

            if cached {
                if let Some(cache) = &cache {
                    let id = req.id();
                    req.set_id(0);
                    cache.set(&req, &msg).await;
                    req.set_id(id);
                }
            }

            (msg, false)
        }
        Err(e) => (convert_error_to_message(&req, e, true), false),
    }
}
