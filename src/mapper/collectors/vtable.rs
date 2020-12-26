use crate::engine::{Interface, InterfaceManager};
use crate::error::{Error, Result};
use crate::mapper::*;

use std::cell::RefCell;
use std::rc::Rc;

use log::{debug, info, trace, warn};

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

/// Scans the given vtable for potential hooks
pub fn scan_vtable<T: VirtualMemory>(
    process: &mut Win32Process<T>,
    interface_manager: &InterfaceManager,
    vtable: Address,
) -> Result<Vec<Function>> {
    let initial_module = interface_manager
        .modules()
        .iter()
        .find(|m| vtable >= m.base() && vtable < m.base() + m.size())
        .ok_or(Error::Other("unable to find vtable"))?;

    let mut funcs = Vec::new();
    let mut idx = 0;
    loop {
        debug!(
            "checking vtable func {} ({}) at 0x{:x}",
            idx, initial_module.name, vtable
        );
        //debug!("trying to scan vtable idx of interface {}/{} at vtable=0x{:x} idx={}", iface.module_info.name, iface.name, vtable, idx);

        match scan_vtable_fn(process, interface_manager, vtable, idx) {
            Ok(func) => {
                if let Some(func) = func {
                    //warn!("potential hook found in vtable of interface {}/{} at vtable=0x{:x} idx={} addr=0x{:x}");
                    warn!(
                        "HOOKED: {} ({}) / {:x} {:x}",
                        idx,
                        initial_module.name,
                        initial_module.base(),
                        initial_module.base() + initial_module.size()
                    );

                    funcs.push(Function::new(func.address));
                }
            }
            Err(err) => {
                println!("error scanning vt func: {}", err);
                break;
            }
        }

        idx += 1;
    }

    Ok(funcs)
}

/// Scans the given vtable index for a potential hook
pub fn scan_vtable_fn<T: VirtualMemory>(
    process: &mut Win32Process<T>,
    interface_manager: &InterfaceManager,
    vtable: Address,
    idx: usize,
) -> Result<Option<Function>> {
    let func = match process.virt_mem.virt_read_addr32(vtable + idx * 4) {
        Ok(f) => f,
        Err(_) => return Err(Error::Other("unable to read vtable func")),
    };

    scan_fn(process, interface_manager, func)
}

/// Scans the given function for a potential hook
pub fn scan_fn<T: VirtualMemory>(
    process: &mut Win32Process<T>,
    interface_manager: &InterfaceManager,
    func: Address,
) -> Result<Option<Function>> {
    if func.is_null() {
        return Err(Error::Other("func is null"));
    }

    /*
    let page_info = match process.virt_mem.virt_page_info(func) {
        Ok(p) => p,
        Err(_) => return Err(Error::Other("unable to get page info for func")),
    };

    // only allow valid pages
    if page_info.page_type.contains(PageType::NOEXEC) {
        // we hit a non executable page, end of vtable
        return Err(Error::Other("func points to non executable page"));
    }
    */

    // TODO: check if function falls in any regular valve module and break
    // TODO: if module is not mapped, add it to the suspect list

    match interface_manager
        .modules()
        .iter()
        .find(|m| func >= m.base() && func < m.base() + m.size())
    {
        Some(m) => {
            debug!("{} found in module: {}", func, m.name());
            Ok(None)
        }
        None => Ok(Some(Function::new(func))),
    }
}
