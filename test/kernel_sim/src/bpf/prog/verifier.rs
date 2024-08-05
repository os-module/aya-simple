use alloc::{sync::Arc, vec::Vec};

use aya_obj::generated::{BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE};
use rbpf::{ebpf, ebpf::to_insn_vec};

use crate::{
    bpf::{
        map::BpfMap,
        prog::{BpfProg, VerifierLogLevel},
    },
    error::KError,
    get_file, Result,
};

/// The BPF program verifier.
///
/// See https://docs.kernel.org/bpf/verifier.html
#[derive(Debug)]
pub struct BpfProgVerifier<'a> {
    prog: BpfProg,
    log_level: VerifierLogLevel,
    log_buf: &'a mut [u8],
}

impl<'a> BpfProgVerifier<'a> {
    pub fn new(prog: BpfProg, log_level: VerifierLogLevel, log_buf: &'a mut [u8]) -> Self {
        Self {
            prog,
            log_level,
            log_buf,
        }
    }
    /// Relocate the program.
    ///
    /// This function will relocate the program, and update the program's instructions.
    fn relocation(&mut self) -> Result<()> {
        let instructions = self.prog.insns_mut();
        let instructions_slice = unsafe {
            core::slice::from_raw_parts(instructions.as_ptr() as *const u8, instructions.len() * 8)
        };
        let mut fmt_insn = to_insn_vec(instructions_slice);
        let mut index = 0;
        loop {
            if index >= fmt_insn.len() {
                break;
            }
            let mut insn = fmt_insn[index].clone();
            if insn.opc == ebpf::LD_DW_IMM {
                // relocate the instruction
                let mut next_insn = fmt_insn[index + 1].clone();
                // the imm is the map_fd because user lib has already done the relocation
                let map_fd = insn.imm as usize;
                let src_reg = insn.src;
                // See https://www.kernel.org/doc/html/latest/bpf/standardization/instruction-set.html#id23
                let ptr = match src_reg as u32 {
                    BPF_PSEUDO_MAP_VALUE => {
                        // dst = map_val(map_by_fd(imm)) + next_imm
                        // map_val(map) gets the address of the first value in a given map
                        let file = get_file(map_fd).unwrap();
                        let bpf_map = file
                            .downcast_arc::<BpfMap>()
                            .map_err(|_| KError::KInvalid)
                            .unwrap();
                        let first_value_ptr = bpf_map.inner_map().lock().first_value_ptr() as usize;
                        let offset = next_insn.imm as usize;
                        info!(
                            "Relocate for BPF_PSEUDO_MAP_VALUE, instruction index: {}, map_fd: {}",
                            index, map_fd
                        );
                        Some(first_value_ptr + offset)
                    }
                    BPF_PSEUDO_MAP_FD => {
                        // dst = map_by_fd(imm)
                        // map_by_fd(imm) means to convert a 32-bit file descriptor into an address of a map
                        let file = get_file(map_fd).unwrap();
                        let bpf_map = file
                            .downcast_arc::<BpfMap>()
                            .map_err(|_| KError::KInvalid)
                            .unwrap();
                        // todo!(warning: We need release after prog unload)
                        let map_ptr = Arc::into_raw(bpf_map) as usize;
                        info!(
                            "Relocate for BPF_PSEUDO_MAP_FD, instruction index: {}, map_fd: {}",
                            index, map_fd
                        );
                        Some(map_ptr)
                    }
                    ty => {
                        error!(
                            "relocation for ty: {} not implemented, instruction index: {}",
                            ty, index
                        );
                        None
                    }
                };
                if let Some(ptr) = ptr {
                    // The current ins store the map_data_ptr low 32 bits,
                    // the next ins store the map_data_ptr high 32 bits
                    insn.imm = ptr as i32;
                    next_insn.imm = (ptr >> 32) as i32;
                    fmt_insn[index] = insn;
                    fmt_insn[index + 1] = next_insn;
                    index += 2;
                } else {
                    index += 1;
                }
            } else {
                index += 1;
            }
        }
        let fmt_insn = fmt_insn
            .iter()
            .map(|ins| ins.to_vec())
            .flatten()
            .collect::<Vec<u8>>();
        instructions.copy_from_slice(unsafe {
            core::slice::from_raw_parts(fmt_insn.as_ptr() as *const u64, fmt_insn.len() / 8)
        });
        Ok(())
    }

    pub fn verify(mut self) -> Result<BpfProg> {
        self.relocation()?;
        Ok(self.prog)
    }
}
