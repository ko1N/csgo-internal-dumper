use crate::engine::{Interface, InterfaceManager};
use crate::mapper::*;

use std::cell::RefCell;
use std::rc::Rc;

use log::{debug, info, trace, warn};

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

use memflow_win32::error::{Error, Result}; // TODO: custom error

/// Scans all Source Engine Interfaces in the target process for potential VTable hooks
pub struct InterfaceCollector<'a, T> {
    process: Win32Process<T>,
    interface_manager: &'a InterfaceManager,
}

impl<'a, T: VirtualMemory> InterfaceCollector<'a, T> {
    pub fn new(process: Win32Process<T>, interface_manager: &'a InterfaceManager) -> Self {
        Self {
            process,
            interface_manager,
        }
    }
}

impl<'a, T: VirtualMemory> FunctionCollector for InterfaceCollector<'a, T> {
    fn collect(&mut self) -> Result<Vec<Function>> {
        // get all interfaces
        let interfaces = self.interface_manager.interfaces();

        // scan all vtables
        let mut funcs = Vec::new();
        for iface in interfaces.iter() {
            if let Ok(mut fns) = scan_vtable(&mut self.process, iface) {
                funcs.append(&mut fns);
            }
        }

        Ok(funcs)
    }
}

/// Scans the VTable of a Source Engine Interface for potential hooks
fn scan_vtable<T: VirtualMemory>(
    process: &mut Win32Process<T>,
    iface: &Interface,
) -> Result<Vec<Function>> {
    let vtable = process.virt_mem.virt_read_addr32(iface.address.into())?;
    if vtable.is_null() {
        return Err(Error::Other("invalid vtable pointer"));
    }
    info!(
        "scanning vtable of interface {}/{} at 0x{:x}",
        iface.module_info.name, iface.name, vtable
    );

    let mut funcs = Vec::new();
    let mut idx = 0;
    'outer: loop {
        let func = match process.virt_mem.virt_read_addr32(vtable + idx * 4) {
            Ok(f) => f,
            Err(_) => break 'outer, // break out at the first invalid func
        };

        if func.is_null() {
            break; // break out at the first invalid func
        }

        debug!(
            "checking vtable func {} of interface {}/{} at 0x{:x}",
            idx, iface.module_info.name, iface.name, vtable
        );

        let page_info = match process.virt_mem.virt_page_info(func) {
            Ok(p) => p,
            Err(_) => break 'outer, // break out at the first invalid func
        };

        // only allow valid pages
        if page_info.page_type.contains(PageType::NOEXEC) {
            break; // we hit a non executable page, end of vtable
        }

        // TODO: check if function falls in any regular valve module and break
        // TODO: if module is not mapped, add it to the suspect list

        if func < iface.module_info.base()
            || func > iface.module_info.base() + iface.module_info.size()
        {
            println!(
                "HOOKED: {} / {:x} {:x} {:x} / {:?}",
                idx,
                func,
                iface.module_info.base(),
                iface.module_info.base() + iface.module_info.size(),
                page_info
            );
            funcs.push(Function::new(func));
        }

        idx += 1;
    }

    Ok(funcs)
}
