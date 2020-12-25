use memflow::dataview::Pod;
use memflow::types::Pointer32;

#[repr(C)]
#[derive(Clone, Debug, Pod)]
pub struct InterfaceReg {
    pub create: u32,
    pub name: u32,
    pub next: Pointer32<InterfaceReg>,
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
    pub createfn: u32,                    // void *
    pub create_eventfn: u32,              // void *
    pub network_name: u32,                // char *
    pub recv_table: Pointer32<RecvTable>, // recv_table_t *
    pub next: Pointer32<ClientClass>,     // client_class_t *
    pub class_id: i32,                    // int
}

#[repr(C)]
#[derive(Clone, Debug, Pod)]
pub struct ConCommandBase {
    pub vt: u32,
    pub next: Pointer32<ConCommandBase>, // ConCommandBase *
    pub registered: u32,                 // bool
    pub name: u32,                       // const char *
    pub description: u32,                // const char *
    pub flags: i32,
    pub pad0: [u8; 0x4],
    pub parent: u32,        // ConCommandBase *
    pub default_value: u32, // const char *
    pub value: u32,         // const char *
    pub value_len: i32,
    pub value_f32: f32,
    pub value_i32: i32,
    pub has_min: u32, // bool
    pub min_f32: f32,
    pub has_max: u32, // bool
    pub max_f32: f32,
}

impl ConCommandBase {
    pub fn new() -> Self {
        Self {
            vt: 0,
            next: Pointer32::NULL,
            registered: 0,
            name: 0,
            description: 0,
            flags: 0,
            pad0: [0, 0, 0, 0],
            parent: 0,
            default_value: 0,
            value: 0,
            value_len: 0,
            value_f32: 0f32,
            value_i32: 0,
            has_min: 0,
            min_f32: 0f32,
            has_max: 0,
            max_f32: 0f32,
        }
    }
}
