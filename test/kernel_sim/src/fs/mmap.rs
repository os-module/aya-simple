use core::ops::Deref;

use bitflags::bitflags;

use crate::{
    get_file,
    perf::{bpf::BpfPerfEvent, PerfEvent},
    Result,
};

bitflags! {
    #[derive(Copy,Clone,Debug)]
    pub struct TmpMMapProt: u32{
        const PROT_NONE = 0;
        const PROT_READ = 1;
        const PROT_WRITE = 2;
        const PROT_EXEC = 4;
    }
    #[derive(Copy,Clone,Debug)]
    pub struct TmpMMapFlag: u32{
        const MAP_FILE = 0x0000;
        const MAP_SHARED = 0x0001;
        const MAP_PRIVATE = 0x0002;
        const MAP_FIXED = 0x0010;
    }
}

pub fn mmap(
    addr: usize,
    len: usize,
    prot: TmpMMapProt,
    flags: TmpMMapFlag,
    fd: usize,
    offset: usize,
) -> Result<usize> {
    info!(
        "<mmap>: addr: {:?}, len: {:#x?}, prot: {:?}, flags: {:?}, fd: {:?}, offset: {:?}",
        addr, len, prot, flags, fd, offset
    );
    let file = get_file(fd).unwrap();
    let file = file
        .downcast_arc::<PerfEvent>()
        .map_err(|_| crate::KError::KInvalid)
        .unwrap();
    let bpf_event_file = file.deref().deref();
    let bpf_event_file = bpf_event_file.downcast_ref::<BpfPerfEvent>().unwrap();
    let res = bpf_event_file.alloc_mmap(len, offset);
    res
}
