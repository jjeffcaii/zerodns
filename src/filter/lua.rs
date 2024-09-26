use super::proto::Filter;
use crate::filter::{Context, FilterFactory, Options};
use crate::protocol::Message;
use async_trait::async_trait;
use mlua::prelude::*;
use mlua::{Function, Lua, UserData, UserDataMethods};
use std::sync::Arc;
use tokio::sync::Mutex;

struct LuaJsonModule;

impl UserData for LuaJsonModule {
    fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("encode", |lua, _, value: mlua::Value| {
            let mut b = smallvec::SmallVec::<[u8; 512]>::new();
            serde_json::to_writer(&mut b, &value).map_err(mlua::Error::external)?;
            lua.create_string(&b[..])
        });
        methods.add_method("decode", |lua, _, input: LuaString| {
            let s = input.to_str()?;
            let v = serde_json::from_str::<serde_json::Value>(s).map_err(mlua::Error::external)?;
            lua.to_value(&v)
        });
    }
}

struct LuaContext(*mut Context);

impl UserData for LuaContext {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {}
}

struct LuaRequest(*mut Message);

impl UserData for LuaRequest {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("question_count", |_, this, ()| {
            let msg = unsafe { this.0.as_mut() }.unwrap();
            Ok(msg.question_count())
        });
        methods.add_method("questions", |lua, this, ()| {
            let mut ret = vec![];

            let msg = unsafe { this.0.as_mut() }.unwrap();
            for next in msg.questions() {
                let tbl = lua.create_table()?;
                tbl.set("name", next.name().to_string())?;
                ret.push(tbl);
            }

            Ok(ret)
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
        debug!("filter on lua");

        {
            let vm = self.vm.lock().await;
            let globals = vm.globals();

            let handler = globals.get::<_, Function>("handle");

            if let Ok(handler) = handler {
                vm.scope(|scope| {
                    let l_ctx = scope.create_userdata(LuaContext(ctx))?;
                    let l_msg = scope.create_userdata(LuaRequest(req))?;

                    handler.call::<_, Option<LuaValue>>((l_ctx, l_msg))?;

                    Ok(())
                })?;
            }
        }

        match &self.next {
            Some(next) => next.handle(ctx, req, res).await,
            None => Ok(()),
        }
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
            let vm = Lua::new();
            vm.load(script).exec()?;

            {
                let globals = vm.globals();

                // bind modules
                // globals.set("json", LuaJsonModule)?;
                // globals.set("urlencoding", LuaUrlEncodingModule)?;
                // globals.set("logger", LuaLogger)?;
            }

            Arc::new(Mutex::new(vm))
        };

        Ok(Self { vm })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_lua() {
        let opts = Options::default();
        let factory = LuaFilterFactory::try_from(&opts).unwrap();
        let f = factory.get();
        assert!(f.is_ok());
    }
}
