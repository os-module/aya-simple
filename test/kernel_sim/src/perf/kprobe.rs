use alloc::{vec, vec::Vec};

use aya_ebpf::bindings::pt_regs;
use spin::Mutex;

use crate::{
    bpf::{prog::BpfProg, BPF_HELPER_FUN_SET},
    error::KError,
    get_file,
    perf::{PerfEventOps, PerfProbeArgs},
};

#[derive(Debug)]
pub struct KprobePerfEvent {
    args: PerfProbeArgs,
    data: Mutex<KprobePerfEventData>,
}

#[derive(Debug)]
pub struct KprobePerfEventData {
    bpf_prog_fd: usize,
    bpf_prog: Vec<u8>,
    enabled: bool,
}

impl PerfEventOps for KprobePerfEvent {
    fn set_bpf_prog(&self, prog_fd: usize) -> crate::Result<()> {
        self.data.lock().bpf_prog_fd = prog_fd;
        let bpf_prog_file = get_file(prog_fd).unwrap();
        let file = bpf_prog_file
            .downcast_arc::<BpfProg>()
            .map_err(|_| KError::KInvalid)
            .unwrap();
        let prog = file.insns();
        let prog_slice =
            unsafe { core::slice::from_raw_parts(prog.as_ptr() as *const u8, prog.len() * 8) };
        self.data.lock().bpf_prog = prog_slice.to_vec();
        Ok(())
    }
    fn enable(&self) -> crate::Result<()> {
        self.data.lock().enabled = true;
        Ok(())
    }
    fn disable(&self) -> crate::Result<()> {
        self.data.lock().enabled = false;
        Ok(())
    }
    fn run_probe(&self) -> crate::Result<()> {
        let data = self.data.lock();
        let mut fake_pt_regs = pt_regs {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: 0,
            rip: 0,
            cs: 0,
            eflags: 0,
            rsp: 0,
            ss: 0,
        };
        let probe_context = unsafe {
            core::slice::from_raw_parts_mut(
                &mut fake_pt_regs as *mut pt_regs as *mut u8,
                core::mem::size_of::<pt_regs>(),
            )
        };
        info!("---------------------Running probe---------------------");
        let mut vm = rbpf::EbpfVmRaw::new(Some(&data.bpf_prog)).unwrap();

        vm.register_helper_set(&*BPF_HELPER_FUN_SET).unwrap();
        let res = vm.execute_program(probe_context).unwrap();
        info!("Program returned: {res:?} ({res:#x})");
        info!("---------------------Probe finished---------------------");
        Ok(())
    }
}

pub fn perf_event_open_kprobe(args: PerfProbeArgs) -> KprobePerfEvent {
    KprobePerfEvent {
        args,
        data: Mutex::new(KprobePerfEventData {
            bpf_prog_fd: 0,
            bpf_prog: vec![],
            enabled: false,
        }),
    }
}
