use memflow::prelude::v1::*;
use memflow_win32::error::Result;
use memflow_win32::prelude::v1::*;

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
}

impl FunctionMapper {
    pub fn new(functions: Vec<Function>) -> Self {
        Self { functions }
    }

    /// Maps out all touched functions, code segments and x-refs
    pub fn map_out_code<T: VirtualMemory>(&mut self, process: &mut Win32Process<T>) {

        // TODO: implement me :)
    }
}
