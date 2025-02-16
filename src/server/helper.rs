use crate::cache::{LoadingCache, LoadingCacheExt};
use crate::error::Error;
use crate::filter::Context;
use crate::handler::Handler;
use crate::protocol::{Flags, Message, RCode};
use crate::{Error as ZError, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn validate_request(req: &Message) -> Result<()> {
    for question in req.questions() {
        for next in question.name() {
            if next.is_empty() {
                continue;
            }
            // must be ascii visible chars:
            if !next.iter().all(|b| (0x20u8..=0x7eu8).contains(b)) {
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

#[inline]
async fn handle_<H>(peer: SocketAddr, req: &Message, h: Arc<H>) -> Result<Message>
where
    H: Handler,
{
    let mut req = Clone::clone(req);
    let mut ctx = Context::default();
    ctx.peer.replace(peer);

    h.handle(&mut ctx, &mut req)
        .await?
        .ok_or_else(|| anyhow!(ZError::ResolveNothing))
}

pub(super) async fn handle<H, C>(
    peer: SocketAddr,
    req: Message,
    h: Arc<H>,
    cache: Option<Arc<C>>,
) -> (Message, bool)
where
    H: Handler,
    C: LoadingCache,
{
    if let Err(e) = validate_request(&req) {
        return (convert_error_to_message(&req, e, false), false);
    }

    let (res, cached) = match cache.as_deref() {
        None => (handle_(peer, &req, h).await, false),
        Some(lc) => {
            let cached = Arc::new(AtomicBool::new(true));

            let res = {
                let req = Clone::clone(&req);
                let cached = Clone::clone(&cached);
                lc.try_get_with_fixed(req, move |req| {
                    cached.store(false, Ordering::SeqCst);
                    async move { handle_(peer, &req, h).await }
                })
                .await
            };

            (res, cached.load(Ordering::Relaxed))
        }
    };

    match res {
        Ok(msg) => (msg, cached),
        Err(e) => (convert_error_to_message(&req, e, true), cached),
    }
}
