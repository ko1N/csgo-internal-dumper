use super::vtable;
use crate::engine::{InterfaceManager, RecvPropManager};
use crate::error::{Error, Result};
use crate::mapper::*;

use log::{debug, warn};

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

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
        let mut funcs = Vec::new();

        for prop in self.recvprop_manager.props().iter() {
            // check if proxyFn falls into a csgo module or error out otherwise
            let proxyfn: Address = prop.prop.proxyfn.into();
            if proxyfn.is_null() {
                continue;
            }

            debug!(
                "trying to scan proxyfn in recvprop '{}' at proxyfn={}",
                prop.path, proxyfn
            );
            match vtable::scan_fn(&mut self.process, &self.interface_manager, proxyfn) {
                Ok(func) => {
                    if let Some(func) = func {
                        warn!(
                            "potential hook found in recvprop '{}' at proxyfn=0x{:x}",
                            prop.path, proxyfn
                        );
                        funcs.push(func)
                    }
                }
                Err(err) => {
                    warn!(
                        "failed to scan proxyfn function at 0x{:x}: {}",
                        proxyfn, err
                    );
                }
            }
        }

        Ok(funcs)
    }
}
