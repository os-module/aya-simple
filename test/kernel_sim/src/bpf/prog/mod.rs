mod verifier;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{ffi::CStr, fmt::Debug, sync::atomic::AtomicUsize};

use aya_obj::generated::{bpf_attach_type, bpf_attr, bpf_prog_type};
use spin::Mutex;

use crate::{
    bpf::{map::BpfMap, prog::verifier::BpfProgVerifier},
    error::KError,
    insert_file, KFile, Result, ID,
};

bitflags::bitflags! {
    /// Used to set the verifier log level flags in [EbpfLoader](EbpfLoader::verifier_log_level()).
    #[derive(Clone, Copy, Debug)]
    pub struct VerifierLogLevel: u32 {
        /// Sets no verifier logging.
        const DISABLE = 0;
        /// Enables debug verifier logging.
        const DEBUG = 1;
        /// Enables verbose verifier logging.
        const VERBOSE = 2 | Self::DEBUG.bits();
        /// Enables verifier stats.
        const STATS = 4;
    }
}

pub struct BpfProgMeta {
    prog_flags: u32,
    prog_type: bpf_prog_type,
    expected_attach_type: bpf_attach_type,
    insns: Vec<u64>,
    license: String,
    kern_version: u32,
    name: String,
}
impl Debug for BpfProgMeta {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BpfProgMeta")
            .field("prog_flags", &self.prog_flags)
            .field("prog_type", &self.prog_type)
            .field("expected_attach_type", &self.expected_attach_type)
            .field("insns_len", &self.insns.len())
            .field("license", &self.license)
            .field("kern_version", &self.kern_version)
            .field("name", &self.name)
            .finish()
    }
}

#[derive(Debug)]
pub struct BpfProgVerifierInfo {
    /// This attribute specifies the level/detail of the log output. Valid values are.
    log_level: VerifierLogLevel,
    /// This attributes indicates the size of the memory region in bytes
    /// indicated by `log_buf` which can safely be written to by the kernel.
    log_buf_size: u32,
    /// This attributes can be set to a pointer to a memory region
    /// allocated/reservedby the loader process where the verifier log will
    /// be written to.
    /// The detail of the log is set by log_level. The verifier log
    /// is often the only indication in addition to the error code of
    /// why the syscall command failed to load the program.
    ///
    /// The log is also written to on success. If the kernel runs out of
    /// space in the buffer while loading, the loading process will fail
    /// and the command will return with an error code of -ENOSPC. So it
    /// is important to correctly size the buffer when enabling logging.
    log_buf_ptr: usize,
}

impl From<&bpf_attr> for BpfProgVerifierInfo {
    fn from(attr: &bpf_attr) -> Self {
        unsafe {
            let u = &attr.__bindgen_anon_3;
            Self {
                log_level: VerifierLogLevel::from_bits_truncate(u.log_level),
                log_buf_size: u.log_size,
                log_buf_ptr: u.log_buf as usize,
            }
        }
    }
}

impl From<&bpf_attr> for BpfProgMeta {
    fn from(attr: &bpf_attr) -> Self {
        unsafe {
            let u = &attr.__bindgen_anon_3;
            let prog_type = core::mem::transmute::<u32, bpf_prog_type>(u.prog_type);
            let expected_attach_type =
                core::mem::transmute::<u32, bpf_attach_type>(u.expected_attach_type);
            let insns =
                core::slice::from_raw_parts(u.insns as *const u64, u.insn_cnt as usize).to_vec();
            let name_slice =
                core::slice::from_raw_parts(u.prog_name.as_ptr() as *const u8, u.prog_name.len());
            let prog_name = CStr::from_bytes_until_nul(name_slice)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let license_start_ptr = u.license as *const u8;
            let mut license_count = 0;
            while *license_start_ptr.add(license_count) != 0 {
                license_count += 1;
            }
            let license_slice = core::slice::from_raw_parts(license_start_ptr, license_count);
            let license = core::str::from_utf8(license_slice).unwrap().to_string();
            let log_level = VerifierLogLevel::from_bits_truncate(u.log_level);

            Self {
                prog_flags: u.prog_flags,
                prog_type,
                expected_attach_type,
                insns,
                license,
                kern_version: u.kern_version,
                name: prog_name,
            }
        }
    }
}

#[derive(Debug)]
pub struct BpfProg {
    meta: BpfProgMeta,
}

impl BpfProg {
    pub fn new(meta: BpfProgMeta) -> Self {
        Self { meta }
    }

    pub fn insns(&self) -> &[u64] {
        &self.meta.insns
    }

    pub fn insns_mut(&mut self) -> &mut [u64] {
        &mut self.meta.insns
    }
}

impl KFile for BpfProg {
    fn type_name(&self) -> &'static str {
        "BpfProg"
    }
    fn readable(&self) -> bool {
        panic!("BpfProg is not readable");
    }
}

/// Load a BPF program into the kernel.
///
/// See https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_PROG_LOAD/
pub fn bpf_prog_load(attr: &bpf_attr) -> Result<i32> {
    let args = BpfProgMeta::from(attr);
    info!("bpf_prog_load: {:#?}", args);
    let log_info = BpfProgVerifierInfo::from(attr);
    info!("bpf_prog_load: {:#?}", log_info);
    let prog = BpfProg::new(args);
    let prog = BpfProgVerifier::new(prog, log_info.log_level, &mut []).verify()?;

    let id = insert_file(Arc::new(prog));
    info!("created prog with fd: [{}]", id);
    Ok(id as i32)
}
