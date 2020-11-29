use super::InterfaceManager;

use std::collections::HashMap;
use std::mem::size_of;

use log::{debug, error};

use dataview::Pod;

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;
use memflow_win32::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct RecvPropManager {
    classes_list_head_ptr: Address,
    recvprops: HashMap<String, Address>,
}

#[allow(dead_code)]
impl RecvPropManager {
    pub fn new<T: VirtualMemory>(
        process: &mut Win32Process<T>,
        iface_man: &InterfaceManager,
    ) -> Result<Self> {
        let client_ptr = iface_man
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

        Ok(Self {
            classes_list_head_ptr,
            recvprops: HashMap::new(),
        })
    }

    pub fn dump<T: VirtualMemory>(&self, ctx: &mut GameContext<T>) -> Result<()> {
        let virt_mem = &mut ctx.process.virt_mem;

        let mut client_class: ClientClass = virt_mem.virt_read(self.classes_list_head_ptr)?;

        loop {
            let recv_table: RecvTable = virt_mem.virt_read(client_class.recv_table.into())?;
            self.dump_datatable(virt_mem, &recv_table, 0, 0).ok();

            if client_class.next == 0 {
                break;
            }
            virt_mem.virt_read_into(client_class.next.into(), &mut client_class)?;
        }

        println!("done");
        Ok(())
    }

    fn dump_datatable<T>(
        &self,
        virt_mem: &mut T,
        recv_table: &RecvTable,
        depth: i32,
        offset: u32,
    ) -> Result<()>
    where
        T: VirtualMemory,
    {
        let mut tabs = String::new();
        for _ in 0..depth {
            tabs += "\t";
        }

        if depth == 0 {
            let net_table_name = virt_mem.virt_read_cstr(recv_table.net_table_name.into(), 1024)?;
            println!("{}{}", tabs, net_table_name);
        }

        for i in 0..recv_table.prop_num {
            let recv_prop: RecvProp = virt_mem
                .virt_read(Address::from(recv_table.props) + i as usize * size_of::<RecvProp>())?;

            let var_name = virt_mem.virt_read_cstr(recv_prop.var_name.into(), 1024)?;

            if recv_prop.recv_type == 6 {
                let data_table = recv_prop.data_table.deref(virt_mem)?;

                let data_table_name =
                    virt_mem.virt_read_cstr(data_table.net_table_name.into(), 1024)?;

                println!(
                    "{}\t{}: 0x{:X} {}",
                    tabs, var_name, recv_prop.offset, data_table_name
                );

                if var_name != "baseclass" {
                    self.dump_datatable(
                        virt_mem,
                        &data_table,
                        depth + 1,
                        offset + recv_prop.offset as u32,
                    )?;
                }
            } else {
                println!(
                    "{}\t{}: 0x{:X}",
                    tabs,
                    var_name,
                    offset + recv_prop.offset as u32
                );
            }
        }

        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Debug, Pod)]
pub struct RecvTable {
    pub props: u32,          // recv_prop_t *
    pub prop_num: i32,       // int
    pub decoder: u32,        // void *
    pub net_table_name: u32, // char *
    pub initialized: u32,    // bool
    pub in_main_list: u32,   // bool
}

#[repr(C)]
#[derive(Clone, Debug, Pod)]
pub struct RecvProp {
    pub var_name: u32,                    // char *
    pub recv_type: i32,                   // int
    pub flags: i32,                       // int
    pub string_buffer_size: i32,          // int
    pub inside_array: i32,                // bool
    pub extra_data: u32,                  // const void *
    pub array_prop: u32,                  // recv_prop_t *
    pub array_length_proxy: u32,          // void *
    pub proxyfn: u32,                     // void *
    pub data_table_proxyfn: u32,          // void *
    pub data_table: Pointer32<RecvTable>, // recv_table_t *
    pub offset: i32,                      // int
    pub element_stride: i32,              // int
    pub element_num: i32,                 // int
    pub parent_array_prop_name: u32,      // const char *
}

#[repr(C)]
#[derive(Clone, Debug, Pod)]
pub struct ClientClass {
    pub createfn: u32,       // void *
    pub create_eventfn: u32, // void *
    pub network_name: u32,   // char *
    pub recv_table: u32,     // recv_table_t *
    pub next: u32,           // client_class_t *
    pub class_id: i32,       // int
}
