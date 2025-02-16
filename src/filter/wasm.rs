use super::{Context, Filter, FilterFactory, Options};
use crate::protocol::Message;
use crate::Result;
use async_trait::async_trait;
use std::result::Result as StdResult;
use wasmedge_sdk::{params, Module, Store, VmBuilder, WasmVal};

struct WasmFilter {
    next: Option<Box<dyn Filter>>,
    module: Module,
}

#[async_trait]
impl Filter for WasmFilter {
    async fn handle(
        &self,
        ctx: &mut Context,
        req: &mut Message,
        res: &mut Option<Message>,
    ) -> Result<()> {
        let vm = {
            let store = Store::new()?;
            let vm = VmBuilder::new().with_store(store).build()?;
            vm.register_module(Some("extern"), Clone::clone(&self.module))?
        };

        let res = vm.run_func(Some("extern"), "add", params!(1_i32, 2_i32))?;

        todo!()
    }

    fn set_next(&mut self, next: Box<dyn Filter>) {
        self.next.replace(next);
    }
}

struct WasmFilterFactory {
    module: Module,
}

impl FilterFactory for WasmFilterFactory {
    type Item = WasmFilter;

    fn get(&self) -> Result<Self::Item> {
        Ok(WasmFilter {
            next: None,
            module: Clone::clone(&self.module),
        })
    }
}

impl TryFrom<&Options> for WasmFilterFactory {
    type Error = anyhow::Error;

    fn try_from(value: &Options) -> StdResult<Self, Self::Error> {
        let path = value
            .get("path")
            .ok_or_else(|| anyhow!("the property of 'path' is required"))?
            .as_str()
            .ok_or_else(|| anyhow!("invalid 'path' format"))?;

        let module = Module::from_file(None, path)?;

        Ok(Self { module })
    }
}
