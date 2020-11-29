use dataview::Pod;

use memflow::types::Pointer32;

#[repr(C)]
#[derive(Clone, Debug, Pod)]
pub struct InterfaceReg {
    pub create: u32,
    pub name: u32,
    pub next: u32,
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
