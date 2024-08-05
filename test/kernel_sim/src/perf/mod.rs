pub mod bpf;
pub mod kprobe;
mod sample;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
};
use core::{
    ffi::{c_int, c_uint, c_void},
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::atomic::AtomicUsize,
};

use aya_obj::generated::perf_event_attr;
use bitflags::bitflags;
use downcast_rs::{impl_downcast, DowncastSync};
use shim_std::libc::pid_t;
use spin::Mutex;

use crate::{
    bpf::prog::BpfProg,
    error::KError,
    get_file, insert_file,
    perf::{
        bpf::BpfPerfEvent,
        sample::{PerfEventSampleFormat, PerfSwIds, PerfTypeId},
    },
    KFile, PerfEventIoc, Result, ID,
};

bitflags! {
    #[derive(Debug,Copy, Clone)]
    pub struct PerfEventOpenFlags: u32 {
        const PERF_FLAG_FD_NO_GROUP = 1;
        const PERF_FLAG_FD_OUTPUT = 2;
        const PERF_FLAG_PID_CGROUP = 4;
        const PERF_FLAG_FD_CLOEXEC = 8;
    }
}

#[derive(Debug, Clone)]
pub struct PerfProbeArgs {
    config: PerfSwIds,
    name: String,
    offset: u64,
    size: u32,
    type_: PerfTypeId,
    pid: i32,
    cpu: i32,
    group_fd: i32,
    flags: PerfEventOpenFlags,
    sample_type: Option<PerfEventSampleFormat>,
}

#[no_mangle]
pub extern "C" fn perf_event_open(
    attr: *const perf_event_attr,
    pid: pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_uint,
) -> c_int {
    let args = unsafe {
        let attr = &*attr;

        let ty = PerfTypeId::try_from(attr.type_).unwrap();
        let config = PerfSwIds::try_from(attr.config as u32).unwrap();

        let name = if ty == PerfTypeId::PERF_TYPE_MAX {
            let name_ptr = attr.__bindgen_anon_3.config1 as *const u8;
            let mut count = 0;
            while *name_ptr.add(count) != 0 {
                count += 1;
            }
            let slice = core::slice::from_raw_parts(name_ptr, count);
            let name = core::str::from_utf8(slice).unwrap().to_string();
            name
        } else {
            "".to_string()
        };
        let sample_ty = PerfEventSampleFormat::try_from(attr.sample_type as u32).ok();
        let args = PerfProbeArgs {
            config,
            name,
            offset: attr.__bindgen_anon_4.config2,
            size: attr.size,
            type_: ty,
            pid,
            cpu,
            group_fd,
            flags: PerfEventOpenFlags::from_bits_truncate(flags),
            sample_type: sample_ty,
        };
        args
    };
    let res = perf_event_process(args);
    match res {
        Ok(fd) => fd,
        Err(e) => {
            error!("perf_event_open: {:?}", e);
            e as i32
        }
    }
}

pub trait PerfEventOps: Send + Sync + Debug + DowncastSync + 'static {
    fn set_bpf_prog(&self, prog_fd: usize) -> Result<()> {
        panic!("set_bpf_prog not implemented");
    }
    fn enable(&self) -> Result<()> {
        panic!("enable not implemented");
    }
    fn disable(&self) -> Result<()> {
        panic!("disable not implemented");
    }
    fn run_probe(&self) -> Result<()> {
        panic!("run_probe not implemented");
    }
    fn readable(&self) -> bool {
        panic!("readable not implemented");
    }
}

impl_downcast!(sync PerfEventOps);

#[derive(Debug)]
pub struct PerfEvent {
    event: Box<dyn PerfEventOps>,
}

impl PerfEvent {
    pub fn new(event: Box<dyn PerfEventOps>) -> Self {
        Self { event }
    }
}

impl Deref for PerfEvent {
    type Target = Box<dyn PerfEventOps>;

    fn deref(&self) -> &Self::Target {
        &self.event
    }
}

impl DerefMut for PerfEvent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.event
    }
}

impl KFile for PerfEvent {
    fn type_name(&self) -> &'static str {
        "PerfEvent"
    }
    fn readable(&self) -> bool {
        self.event.readable()
    }
}

pub fn perf_event_process(args: PerfProbeArgs) -> Result<i32> {
    info!("perf_event_process: {:#?}", args);
    let event: Box<dyn PerfEventOps> = match args.type_ {
        /// Kprobe
        ///
        /// See /sys/bus/event_source/devices/kprobe/type
        PerfTypeId::PERF_TYPE_MAX => {
            let kprobe_event = kprobe::perf_event_open_kprobe(args);
            Box::new(kprobe_event)
        }
        PerfTypeId::PERF_TYPE_SOFTWARE => {
            // For bpf prog output
            assert_eq!(args.config, PerfSwIds::PERF_COUNT_SW_BPF_OUTPUT);
            assert_eq!(
                args.sample_type,
                Some(PerfEventSampleFormat::PERF_SAMPLE_RAW)
            );
            let bpf_event = bpf::perf_event_open_bpf(args);
            Box::new(bpf_event)
        }
        _ => {
            unimplemented!("perf_event_process: unknown type: {:?}", args);
        }
    };
    let perf_event_file = PerfEvent::new(event);
    let id = insert_file(Arc::new(perf_event_file));
    info!("created perf event with fd: [{}]", id);
    Ok(id as i32)
}

pub fn perf_event_ioctl(fd: usize, request: c_int, arg: usize) -> Result<i64> {
    let event = get_file(fd)
        .unwrap()
        .downcast_arc::<PerfEvent>()
        .map_err(|_| KError::KInvalid)
        .unwrap();
    let req = PerfEventIoc::try_from(request as u32).unwrap();
    info!(
        "perf_event_ioctl: fd: {}, request: {:?}, arg: {}",
        fd, req, arg
    );
    match req {
        PerfEventIoc::Enable => {
            event.enable()?;
            Ok(0)
        }
        PerfEventIoc::Disable => {
            event.disable()?;
            Ok(0)
        }
        PerfEventIoc::SetBpf => {
            info!("perf_event_ioctl: PERF_EVENT_IOC_SET_BPF, arg: {}", arg);
            let bpf_prog_fd = arg;
            event.set_bpf_prog(bpf_prog_fd)?;
            FAKE_PERF_EVENT_FD.store(fd, core::sync::atomic::Ordering::SeqCst);
            Ok(0)
        }
        _ => {
            unimplemented!("perf_event_ioctl: unknown request: {}", request);
        }
    }
}

pub fn perf_event_output(ctx: *mut c_void, fd: usize, flags: u32, data: &[u8]) -> Result<()> {
    let file = get_file(fd)
        .unwrap()
        .downcast_arc::<PerfEvent>()
        .map_err(|_| KError::KInvalid)
        .unwrap();
    info!("perf_event_output: fd: {}, flags: {:x?}", fd, flags);
    let bpf_event_file = file.deref().deref();
    let bpf_event_file = bpf_event_file.downcast_ref::<BpfPerfEvent>().unwrap();
    bpf_event_file.write_event(data)?;
    Ok(())
}

/// For test
pub static FAKE_PERF_EVENT_FD: AtomicUsize = AtomicUsize::new(0);
