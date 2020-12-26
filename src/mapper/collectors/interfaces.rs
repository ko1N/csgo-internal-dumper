use super::vtable;
use crate::engine::{Interface, InterfaceManager};
use crate::error::{Error, Result};
use crate::mapper::*;

use std::cell::RefCell;
use std::rc::Rc;

use log::{debug, info, trace, warn};

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

/// Scans all Source Engine Interfaces in the target process for potential VTable hooks
pub struct InterfaceCollector<'a, T> {
    process: Win32Process<T>,
    interface_manager: &'a InterfaceManager,
}

impl<'a, T> InterfaceCollector<'a, T> {
    pub fn new(process: Win32Process<T>, interface_manager: &'a InterfaceManager) -> Self {
        Self {
            process,
            interface_manager,
        }
    }
}

impl<'a, T: VirtualMemory> FunctionCollector for InterfaceCollector<'a, T> {
    fn collect(&mut self) -> Result<Vec<Function>> {
        // TODO: add command line switch to change this behavior
        //self.scan_all_interfaces()
        self.scan_specific_interfaces()
    }
}

impl<'a, T: VirtualMemory> InterfaceCollector<'a, T> {
    /// Scans all interfaces for potential vtable hooks.
    /// This tends to be fairly unreliable due to memory being paged out at times.
    // #[allow(unused)]
    fn scan_all_interfaces(&mut self) -> Result<Vec<Function>> {
        // get all interfaces
        let interfaces = self.interface_manager.interfaces();

        // scan all vtables
        let mut funcs = Vec::new();
        for iface in interfaces.iter() {
            if let Ok(mut fns) = self.scan_vtable(iface) {
                funcs.append(&mut fns);
            }
        }

        Ok(funcs)
    }

    /// Scans only specific (usually cheat related) interfaces and functions.
    /// This tends to be more reliable due to the vtable size being unknown and additional paged out pages.
    fn scan_specific_interfaces(&mut self) -> Result<Vec<Function>> {
        let mut funcs = Vec::new();

        if let Some(vclient) = self.interface_manager.get("client.dll", "VClient018") {
            info!("Scanning for hooks in VClient018");
            // CreateMove @ 22
            // PaintTraverse @ 41
            funcs.append(&mut self.scan_vtable_fns(&vclient, &[22, 41])?);
        }

        // TODO: add more vtable checks :)

        Ok(funcs)
    }

    /// Scans the VTable of a Source Engine Interface for potential hooks
    fn scan_vtable(&mut self, iface: &Interface) -> Result<Vec<Function>> {
        let vtable = self
            .process
            .virt_mem
            .virt_read_addr32(iface.address.into())?;
        if vtable.is_null() {
            return Err(Error::Other("invalid vtable pointer"));
        }
        info!(
            "scanning vtable of interface {}/{} at 0x{:x}",
            iface.module_info.name, iface.name, vtable
        );

        vtable::scan_vtable(&mut self.process, &self.interface_manager, vtable)
    }

    fn scan_vtable_fns(&mut self, iface: &Interface, idxs: &[usize]) -> Result<Vec<Function>> {
        let vtable = self
            .process
            .virt_mem
            .virt_read_addr32(iface.address.into())?;
        if vtable.is_null() {
            return Err(Error::Other("invalid vtable pointer"));
        }
        info!(
            "scanning vtable entries of interface {}/{} at vtable=0x{:x}",
            iface.module_info.name, iface.name, vtable
        );

        let mut funcs = Vec::new();
        for idx in idxs.into_iter() {
            debug!(
                "trying to scan vtable idx of interface {}/{} at vtable=0x{:x} idx={}",
                iface.module_info.name, iface.name, vtable, idx
            );
            match vtable::scan_vtable_fn(&mut self.process, &self.interface_manager, vtable, *idx) {
                Ok(func) => {
                    if let Some(func) = func {
                        warn!("potential hook found in vtable of interface {}/{} at vtable=0x{:x} idx={} addr=0x{:x}",
                    iface.module_info.name, iface.name, vtable, idx, func.address);
                        funcs.push(func)
                    }
                }
                Err(err) => {
                    warn!("failed to scan vtable function at {}: {}", idx, err);
                }
            }
        }
        Ok(funcs)
    }
}
