#![feature(c_variadic)]
#![allow(unused)]
#![no_std]

extern crate alloc;

#[macro_use]
extern crate log;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{ffi::c_int, fmt::Debug, sync::atomic::AtomicUsize};

use aya_obj::generated::{
    AYA_PERF_EVENT_IOC_DISABLE, AYA_PERF_EVENT_IOC_ENABLE, AYA_PERF_EVENT_IOC_SET_BPF,
};
use downcast_rs::{impl_downcast, DowncastSync};
use int_enum::IntEnum;
use spin::Mutex;

use crate::{
    error::KError,
    perf::{PerfEvent, FAKE_PERF_EVENT_FD},
};

mod bpf;
mod error;
mod fs;
mod perf;
mod util;

type Result<T> = core::result::Result<T, error::KError>;

const PERF_EVENT_IOC_ENABLE: c_int = 9216;
const PERF_EVENT_IOC_DISABLE: c_int = 9217;
const PERF_EVENT_IOC_SET_BPF: c_int = 1074013192;

#[repr(u32)]
#[derive(Debug, Copy, Clone, IntEnum)]
pub enum PerfEventIoc {
    Enable = 9216,
    Disable = 9217,
    SetBpf = 1074013192,
}

pub trait KFile: DowncastSync + Debug {
    fn type_name(&self) -> &'static str;
    fn readable(&self) -> bool;
}

impl_downcast!(sync KFile);

pub struct PerCpuInfoImpl;

impl PerCpuInfo for PerCpuInfoImpl {
    fn cpu_id() -> u32 {
        0
    }
    fn num_cpus() -> u32 {
        1
    }
}

pub trait PerCpuInfo: Send + Sync + 'static {
    /// Get the CPU ID of the current CPU.
    fn cpu_id() -> u32;
    /// Get the number of CPUs.
    fn num_cpus() -> u32;
}

static ID: AtomicUsize = AtomicUsize::new(10);
static FILES: Mutex<BTreeMap<usize, Arc<dyn KFile>>> = Mutex::new(BTreeMap::new());

pub fn insert_file(file: Arc<dyn KFile>) -> usize {
    let id = ID.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    let mut events = FILES.lock();
    events.insert(id, file);
    id
}

pub fn get_file(id: usize) -> Option<Arc<dyn KFile>> {
    let files = FILES.lock();
    files.get(&id).map(|f| f.clone())
}

pub fn remove_file(id: usize) -> Result<()> {
    let mut files = FILES.lock();
    let file = files.remove(&id);
    if let Some(file) = file {
        info!("remove_file [{}] {:?}", id, file.type_name());
        Ok(())
    } else {
        Err(error::KError::KENOENT)
    }
}

pub fn file_readable(fd: usize) -> bool {
    let files = FILES.lock();
    let file = files.get(&fd).unwrap();
    file.readable()
}

pub fn fake_kernel_event_loop() {
    let fake_perf_event_fd = FAKE_PERF_EVENT_FD.load(core::sync::atomic::Ordering::Relaxed);
    let event = get_file(fake_perf_event_fd)
        .unwrap()
        .downcast_arc::<PerfEvent>()
        .map_err(|_| KError::KInvalid)
        .unwrap();

    event.run_probe().unwrap();
}
