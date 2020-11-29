use std::collections::HashMap;

use log::{debug, info, trace, warn};

use dataview::Pod;

use memflow::prelude::v1::*;
use memflow_win32::error::{Error, Result};
use memflow_win32::prelude::v1::*;

use pelite::pe32::{
    exports::{Export, GetProcAddress},
    *,
};

#[derive(Clone, Debug)]
pub struct Interface {
    pub module_info: Win32ModuleInfo,
    pub name: String,
    pub address: u32,
}

#[repr(C)]
#[derive(Clone, Debug, Pod)]
struct InterfaceReg {
    create: u32,
    name: u32,
    next: u32,
}

pub struct InterfaceManager {
    interfaces: Vec<Interface>,
    interfaces_map: HashMap<String, Interface>,
}

impl InterfaceManager {
    pub fn new<T: VirtualMemory>(process: &mut Win32Process<T>) -> Result<Self> {
        let mut interfaces = Vec::new();

        let modules = process.module_list()?;
        for module in modules.iter() {
            if let Ok(mut ifaces) = find_all_interfaces(process, module.to_owned()) {
                interfaces.append(&mut ifaces);
            } else {
                warn!("unable to parse interfaces for module '{}'", module.name());
            }
        }

        let interfaces_map = interfaces
            .iter()
            .map(|i| (i.name.clone(), i.clone()))
            .collect();

        Ok(Self {
            interfaces,
            interfaces_map,
        })
    }

    pub fn interfaces<'a>(&'a self) -> &'a Vec<Interface> {
        &self.interfaces
    }

    pub fn modules(&self) -> Vec<Win32ModuleInfo> {
        let module_map = self
            .interfaces
            .iter()
            .map(|i| (i.module_info.name().clone(), i.module_info.clone()))
            .collect::<HashMap<String, Win32ModuleInfo>>();

        module_map.into_iter().map(|(_, m)| m).collect::<Vec<_>>()
    }

    pub fn get(&self, name: &str) -> Option<Interface> {
        match self.interfaces_map.get(name) {
            Some(iface) => Some(iface.clone()),
            None => None,
        }
    }

    pub fn get_handle(&self, name: &str) -> Option<Address> {
        let iface = self.get(name)?;
        Some(iface.address.into())
    }
}

/// Returns a list of all Source Engine Interfaces found in a given module
fn find_all_interfaces<T: VirtualMemory>(
    process: &mut Win32Process<T>,
    module_info: Win32ModuleInfo,
) -> Result<Vec<Interface>> {
    debug!(
        "scanning module {}: 0x{:x} (0x{:x})",
        module_info.name(),
        module_info.base(),
        module_info.size()
    );

    // parse pe image
    let mut image = vec![0u8; module_info.size()];
    process
        .virt_mem
        .virt_read_raw_into(module_info.base, &mut image)
        .data_part()?;
    let pe = PeView::from_bytes(&image).map_err(|_| Error::Other("unable to parse pe image"))?;

    // find export "CreateInterface"
    let create_interface_fn = match pe.get_export("CreateInterface").map_err(Error::PE)? {
        Export::Symbol(s) => module_info.base() + *s as usize,
        Export::Forward(_) => {
            return Err(Error::Other(
                "CreateInterface found but it was a forwarded export",
            ))
        }
    };
    debug!(
        "create_interface_fn={:x}",
        create_interface_fn - module_info.base()
    );

    // find internal linked list
    let ci_jmp: u32 = process.virt_mem.virt_read(create_interface_fn + 0x5)?;
    trace!("ci_jmp={:x}", ci_jmp);

    let ci_followed = Address::from(create_interface_fn.as_u32() + 0x5 + 0x4 + ci_jmp);
    trace!(
        "ci_followed={:x}",
        Address::from(ci_followed) - module_info.base()
    );

    let ci_sig: u16 = process.virt_mem.virt_read(ci_followed + 0x4)?;
    trace!("ci_sig={:x}", ci_sig);
    if ci_sig != 0x358B {
        return Err(Error::Other("unable to validate CreateInterface signature"));
    }

    let mut temp: u32 = process.virt_mem.virt_read(ci_followed + 0x6)?;
    process.virt_mem.virt_read_into(temp.into(), &mut temp)?;

    // read interface
    let mut reg: InterfaceReg = process.virt_mem.virt_read(temp.into())?;

    let mut interfaces = Vec::new();
    loop {
        let name = process.virt_mem.virt_read_cstr(reg.name.into(), 128)?;
        let address: u32 = process
            .virt_mem
            .virt_read(Address::from(reg.create) + 0x1)?;
        if address != 0 {
            info!("interface {} found at {:x}", name, address);
            interfaces.push(Interface {
                module_info: module_info.clone(),
                name,
                address,
            });
        } else {
            warn!("instance pointer of interface {} is invalid", name);
        }

        if reg.next == 0 {
            break;
        }
        process.virt_mem.virt_read_into(reg.next.into(), &mut reg)?;
    }

    Ok(interfaces)
}