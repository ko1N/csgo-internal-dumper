use crate::engine::{CVarManager, Interface, InterfaceManager};
use crate::error::{Error, Result};
use crate::mapper::*;

use std::cell::RefCell;
use std::rc::Rc;

use log::{debug, info, trace, warn};

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

/// Scans all Source Engine Interfaces in the target process for potential VTable hooks
pub struct ConVarCollector<'a, T> {
    process: Win32Process<T>,
    cvar_manager: &'a CVarManager,
}

impl<'a, T> ConVarCollector<'a, T> {
    pub fn new(process: Win32Process<T>, cvar_manager: &'a CVarManager) -> Self {
        Self {
            process,
            cvar_manager,
        }
    }
}

impl<'a, T: VirtualMemory> FunctionCollector for ConVarCollector<'a, T> {
    fn collect(&mut self) -> Result<Vec<Function>> {
        // get all interfaces
        let cvars = self.cvar_manager.cvars();

        // scan all vtables
        let mut funcs = Vec::new();
        for cvar in cvars.iter() {
            /*
            if let Ok(mut fns) = self.scan_vtable(iface) {
                funcs.append(&mut fns);
            }
            */
            // TODO: scan vtable of cvar for potential hooks
            // (e.g. SetBool/GetBool)
        }

        Ok(funcs)
    }
}

impl<'a, T: VirtualMemory> InterfaceCollector<'a, T> {}
