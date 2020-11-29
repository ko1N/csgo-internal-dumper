use crate::engine::InterfaceManager;
use crate::mapper::*;

/// Scans all RecvTables for Proxy Callbacks
pub struct RecvPropCollector {
    // borrow things
}

impl RecvPropCollector {
    pub fn new() -> Self {
        Self {}
    }
}

/*
impl FunctionCollector for RecvPropCollector {
    fn collect<T: VirtualMemory>(process: &mut Win32Process<T>) -> Result<Vec<Function>> {
        let funcs = Vec::new();

        // TODO: parse recvtables

        Ok(funcs)
    }
}
*/
