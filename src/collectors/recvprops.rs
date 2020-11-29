use crate::engine::{InterfaceManager, RecvPropManager};
use crate::mapper::*;

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

use memflow_win32::error::{Error, Result}; // TODO: custom error

/// Scans all RecvTables for Proxy Callbacks
pub struct RecvPropCollector<'a, T> {
    process: Win32Process<T>,
    interface_manager: &'a InterfaceManager,
    recvprop_manager: &'a RecvPropManager,
}

impl<'a, T> RecvPropCollector<'a, T> {
    pub fn new(
        process: Win32Process<T>,
        interface_manager: &'a InterfaceManager,
        recvprop_manager: &'a RecvPropManager,
    ) -> Self {
        Self {
            process,
            interface_manager,
            recvprop_manager,
        }
    }
}

impl<'a, T: VirtualMemory> FunctionCollector for RecvPropCollector<'a, T> {
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
                        println!("{} found in module: {}", prop.path, m.name());
                    }
                    None => {
                        println!("HOOK: {} not found in any module", prop.path);
                    }
                }
            }
        }

        Ok(funcs)
    }
}
