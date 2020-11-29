use crate::engine::{InterfaceManager, RecvPropManager};
use crate::mapper::*;

use log::{debug, warn};

use memflow::prelude::v1::*;

use memflow_win32::error::Result; // TODO: custom error

/// Scans all RecvTables for Proxy Callbacks
pub struct RecvPropCollector<'a> {
    interface_manager: &'a InterfaceManager,
    recvprop_manager: &'a RecvPropManager,
}

impl<'a> RecvPropCollector<'a> {
    pub fn new(
        interface_manager: &'a InterfaceManager,
        recvprop_manager: &'a RecvPropManager,
    ) -> Self {
        Self {
            interface_manager,
            recvprop_manager,
        }
    }
}

impl<'a> FunctionCollector for RecvPropCollector<'a> {
    fn collect(&mut self) -> Result<Vec<Function>> {
        let funcs = Vec::new();

        let modules = self.interface_manager.modules();

        let props = self.recvprop_manager.props();
        for prop in props.iter() {
            // check if proxyFn falls into a csgo module or error out otherwise
            let proxyfn: Address = prop.prop.proxyfn.into();
            if !proxyfn.is_null() {
                match modules
                    .iter()
                    .find(|m| proxyfn >= m.base() && proxyfn < m.base() + m.size())
                {
                    Some(m) => {
                        debug!("{} found in module: {}", prop.path, m.name());
                    }
                    None => {
                        warn!("HOOK: {} not found in any module", prop.path);
                    }
                }
            }
        }

        Ok(funcs)
    }
}
