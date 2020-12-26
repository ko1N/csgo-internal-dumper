pub mod collectors;
pub use collectors::*;

use crate::error::{Error, Result};

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use log::{info, warn};

use memflow::prelude::v1::*;
use memflow_win32::prelude::v1::*;

use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, Instruction, InstructionInfoFactory, OpKind, RflagsBits,
};

const PAGE_SIZE: usize = 0x1000;

#[derive(Debug, Clone)]
pub struct Function {
    pub address: Address,
    // TODO: add more metadata?
}

impl Function {
    pub fn new(address: Address) -> Self {
        Self { address }
    }
}

/// Trait for individual stages to collect/find potential functions
pub trait FunctionCollector {
    fn collect(&mut self) -> Result<Vec<Function>>;
}

/// The Function mapper will collect all potential 'functions' of the target
/// and then map out all xrefs to all pages in the target
pub struct FunctionMapper {
    functions: Vec<Function>,
    touched_pages: HashMap<u32, bool>,
}

impl FunctionMapper {
    pub fn new(functions: Vec<Function>) -> Self {
        Self {
            functions,
            touched_pages: HashMap::new(),
        }
    }

    /// Maps out all touched functions, code segments and x-refs
    pub fn map_out_code<T: VirtualMemory>(&mut self, process: &mut Win32Process<T>) {
        // TODO: remove clone()
        info!(
            "mapping out an initial set of {} functions",
            self.functions.len()
        );

        for func in self.functions.clone().iter() {
            self.disasm_fn(process, func.address, PAGE_SIZE);
        }

        info!(
            "total number of pages touched: {}",
            self.touched_pages.len()
        );
    }

    /// Dumps all touched pages to the specified folder
    pub fn dump_touched_pages<T: VirtualMemory, P: AsRef<Path>>(
        &self,
        process: &mut Win32Process<T>,
        path: P,
    ) -> Result<()> {
        std::fs::create_dir_all(path.as_ref().clone())?;

        for (&page, _) in self.touched_pages.iter() {
            info!("reading page at page=0x{:x}", page);
            if let Ok(page_buf) = process
                .virt_mem
                .virt_read_raw(page.into(), PAGE_SIZE)
                .data_part()
            {
                if page_buf.iter().find(|&&b| b != 0).is_none() {
                    // empty page (potentially paged out)
                    continue;
                }

                let mut file =
                    File::create(PathBuf::from(path.as_ref()).join(&format!("0x{:x}.dmp", page)))?;
                file.write_all(&page_buf)?;
            }
        }

        Ok(())
    }

    fn disasm_fn<T: VirtualMemory>(
        &mut self,
        process: &mut Win32Process<T>,
        func: Address,
        len: usize,
    ) {
        // check if page is touched or touch it now
        let func_base = func.as_page_aligned(PAGE_SIZE);
        if self.touched_pages.contains_key(&func_base.as_u32()) {
            return;
        }

        info!(
            "disassembling function at addr=0x{:x} base=0x{:x}",
            func, func_base
        );
        self.touched_pages.insert(func_base.as_u32(), true);

        let func_buffer = process
            .virt_mem
            .virt_read_raw(func_base, PAGE_SIZE)
            .data_part()
            .unwrap();

        let mut decoder = Decoder::new(32, func_buffer.as_slice(), DecoderOptions::NONE);
        decoder.set_ip(func.as_u64());

        let mut info_factory = InstructionInfoFactory::new();
        let mut instr = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);

            //let offsets = decoder.get_constant_offsets(&instr);
            //println!("{:016X} {}", instr.ip(), instr);

            // TODO: filter out valid modules

            // TODO: handle the following instructions: mov, call, jmps, anything else that accesses registers

            if instr.is_call_near() || instr.is_call_far() {
                //trace!("following call: {:016X} {}", instr.ip(), instr);
                self.disasm_fn(process, instr.memory_address64().into(), PAGE_SIZE);
            }

            if instr.is_jmp_short() || instr.is_jmp_near() || instr.is_jmp_far() {
                //trace!("following jmp: {:016X} {}", instr.ip(), instr);
                self.disasm_fn(process, instr.memory_address64().into(), PAGE_SIZE);
            }
        }
    }
}
