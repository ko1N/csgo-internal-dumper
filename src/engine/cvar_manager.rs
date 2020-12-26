use super::native::ConCommandBase;
use super::InterfaceManager;
use crate::error::{Error, Result};

use std::collections::HashMap;
use std::convert::TryInto;

use log::debug;

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

#[derive(Clone, Debug)]
pub struct CVarManager {
    cvars: Vec<Address>,
    cvars_map: HashMap<String, Address>,
}

impl CVarManager {
    pub fn new<T: VirtualMemory>(
        process: &mut Win32Process<T>,
        interface_manager: &InterfaceManager,
    ) -> Result<Self> {
        let std_cvar_ptr = interface_manager
            .get_handle("vstdlib.dll", "VEngineCvar007")
            .ok_or_else(|| Error::Other("unable to find interface VEngineCvar007"))?;

        let ccmd_list_head_ptr = process.virt_mem.virt_read_addr32(std_cvar_ptr + 0x34)?;
        debug!("ccmd_list_head_ptr: {}", ccmd_list_head_ptr);

        let cvars = find_all_convars(process, ccmd_list_head_ptr.try_into()?)?;

        Ok(Self {
            cvars,
            cvars_map: HashMap::new(),
        })
    }

    // TODO: do not use address here
    pub fn cvars<'a>(&'a self) -> &'a Vec<Address> {
        &self.cvars
    }
}

pub fn find_all_convars<T: VirtualMemory>(
    process: &mut Win32Process<T>,
    ccmd_list_head_ptr: Pointer32<ConCommandBase>,
) -> Result<Vec<Address>> {
    let cvars = Vec::new();

    let virt_mem = &mut process.virt_mem;

    let mut con_command: ConCommandBase = ccmd_list_head_ptr.deref(virt_mem)?;
    loop {
        let con_command_name = virt_mem.virt_read_cstr(con_command.name.into(), 256)?;
        // TODO: store con_commands
        //println!("con_command_name: {}", con_command_name);

        if con_command.next.is_null() {
            break;
        }
        con_command.next.deref_into(virt_mem, &mut con_command)?;
    }

    /*
    while !cmd_entry_ptr.is_null() {
        if let Ok(cmd) = Self::read_cvar(virt_mem, cmd_entry_ptr + 4) {
            if !cmd.1.is_empty() {
                // TODO:
                println!("found cvar: {}", cmd.1);
                /*
                if name == cmd.1 {
                    return Ok(CVar::with(ctx, cmd.0)?);
                }
                */
            }
        }

        cmd_entry_ptr = virt_mem.virt_read_addr32(cmd_entry_ptr + 4)?;
    }
    */

    Ok(cvars)
}

fn read_cvar<T: VirtualMemory>(virt_mem: &mut T, ptr: Address) -> Result<(Address, String)> {
    let cmd_ptr = virt_mem.virt_read_addr32(ptr)?;
    let cmd = virt_mem.virt_read::<ConCommandBase>(cmd_ptr)?;
    Ok((cmd_ptr, virt_mem.virt_read_cstr(cmd.name.into(), 256)?))
}

/*
#[derive(Clone, Debug)]
pub struct CVar {
    pub addr: Address,
    pub cmd: ConCommandBase,
}

impl CVar {
    pub fn with<T: VirtualMemory>(ctx: &mut GameContext<T>, addr: Address) -> Result<Self> {
        let mut s = Self {
            addr,
            cmd: ConCommandBase::new(),
        };
        s.update(ctx)?;
        Ok(s)
    }

    pub fn update<T: VirtualMemory>(&mut self, ctx: &mut GameContext<T>) -> Result<()> {
        ctx.process
            .virt_mem
            .virt_read_into(self.addr, &mut self.cmd)?;

        // fixup xored values
        unsafe {
            let raw_value: u32 =
                std::mem::transmute::<f32, u32>(self.cmd.value_f32) ^ self.addr.as_u32();
            self.cmd.value_f32 = std::mem::transmute(raw_value);
        }
        unsafe {
            let raw_value: u32 =
                std::mem::transmute::<i32, u32>(self.cmd.value_i32) ^ self.addr.as_u32();
            self.cmd.value_i32 = std::mem::transmute(raw_value);
        }

        Ok(())
    }

    // TODO: add more cvar helper funcs
    pub fn value<T: VirtualMemory>(&mut self, ctx: &mut GameContext<T>) -> Result<String> {
        ctx.process
            .virt_mem
            .virt_read_cstr(self.cmd.value.into(), 256)
            .map_err(Error::from)
    }
}
*/
