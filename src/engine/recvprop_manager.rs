use super::native::{ClientClass, RecvProp, RecvTable};
use super::InterfaceManager;

use std::collections::HashMap;
use std::mem::size_of;

use log::{debug, trace};

use memflow::prelude::v1::*;
use memflow_win32::error::{Error, Result};
use memflow_win32::prelude::v1::*;

#[derive(Clone, Debug)]
pub struct Prop {
    pub path: String,
    pub offset: u32,
    pub prop: RecvProp,
}

#[derive(Clone, Debug)]
pub struct RecvPropManager {
    props: Vec<Prop>,
    props_map: HashMap<String, Prop>,
}

#[allow(dead_code)]
impl RecvPropManager {
    pub fn new<T: VirtualMemory>(
        process: &mut Win32Process<T>,
        interface_manager: &InterfaceManager,
    ) -> Result<Self> {
        let client_ptr = interface_manager
            .get_handle("VClient018")
            .ok_or_else(|| Error::Other("VClient018 could not be found"))?;

        let virt_mem = &mut process.virt_mem;

        let client_vt = virt_mem.virt_read_addr32(client_ptr)?;
        debug!("client_vt={:x}", client_vt);

        // get client classes
        let get_all_classes_fn = virt_mem.virt_read_addr32(client_vt + 8 * 4)?;
        debug!("get_all_classes_fn={:x}", get_all_classes_fn);
        let classes_list_head_ptr_ref = virt_mem.virt_read_addr32(get_all_classes_fn + 1)?;
        debug!("classes_list_head_ptr_ref={:x}", classes_list_head_ptr_ref);
        let classes_list_head_ptr = virt_mem.virt_read_addr32(classes_list_head_ptr_ref)?;
        debug!("classes_list_head_ptr={:x}", classes_list_head_ptr);

        // TODO: parse and store all recvprops
        let props = find_all_recvprops(process, classes_list_head_ptr)?;
        let props_map = props.iter().map(|p| (p.path.clone(), p.clone())).collect();

        Ok(Self { props, props_map })
    }

    pub fn props<'a>(&'a self) -> &'a Vec<Prop> {
        &self.props
    }

    pub fn get(&self, path: &str) -> Option<Prop> {
        match self.props_map.get(path) {
            Some(iface) => Some(iface.clone()),
            None => None,
        }
    }
}

pub fn find_all_recvprops<T: VirtualMemory>(
    process: &mut Win32Process<T>,
    classes_list_head_ptr: Address,
) -> Result<Vec<Prop>> {
    let mut props = Vec::new();

    let virt_mem = &mut process.virt_mem;
    let mut client_class: ClientClass = virt_mem.virt_read(classes_list_head_ptr)?;
    loop {
        let recv_table: RecvTable = virt_mem.virt_read(client_class.recv_table.into())?;
        if let Ok(mut p) = find_props_in_datatable(virt_mem, &recv_table, String::new(), 0) {
            props.append(&mut p);
        }

        if client_class.next == 0 {
            break;
        }
        virt_mem.virt_read_into(client_class.next.into(), &mut client_class)?;
    }

    Ok(props)
}

fn find_props_in_datatable<T>(
    virt_mem: &mut T,
    recv_table: &RecvTable,
    mut path: String,
    offset: u32,
) -> Result<Vec<Prop>>
where
    T: VirtualMemory,
{
    let mut props = Vec::new();

    if path == "" {
        path = virt_mem.virt_read_cstr(recv_table.net_table_name.into(), 1024)?;
    }

    for i in 0..recv_table.prop_num {
        let recv_prop: RecvProp = virt_mem
            .virt_read(Address::from(recv_table.props) + i as usize * size_of::<RecvProp>())?;

        let var_name = virt_mem.virt_read_cstr(recv_prop.var_name.into(), 1024)?;

        if recv_prop.recv_type == 6 {
            let data_table = recv_prop.data_table.deref(virt_mem)?;

            let data_table_name =
                virt_mem.virt_read_cstr(data_table.net_table_name.into(), 1024)?;

            trace!(
                "{}.{}: 0x{:X} {}",
                path,
                var_name,
                recv_prop.offset,
                data_table_name
            );

            if var_name != "baseclass" {
                if let Ok(mut p) = find_props_in_datatable(
                    virt_mem,
                    &data_table,
                    format!("{}.{}", path, var_name),
                    offset + recv_prop.offset as u32,
                ) {
                    props.append(&mut p);
                }
            }
        } else {
            trace!(
                "{}.{}: 0x{:X}",
                path,
                var_name,
                offset + recv_prop.offset as u32
            );

            props.push(Prop {
                path: format!("{}.{}", path, var_name),
                offset: offset + recv_prop.offset as u32,
                prop: recv_prop.clone(),
            })
        }
    }

    Ok(props)
}
