mod print;

use alloc::{collections::BTreeMap, sync::Arc};
use core::ffi::c_void;

use aya_obj::generated::BPF_F_CURRENT_CPU;
use spin::Lazy;

use crate::{bpf::map::BpfMap, get_file, perf::PerfEvent, PerCpuInfo, PerCpuInfoImpl, Result};

type RawBPFHelperFn = fn(u64, u64, u64, u64, u64) -> u64;

macro_rules! define_func {
    ($name:ident) => {
        core::mem::transmute::<_, RawBPFHelperFn>($name as usize)
    };
}

/// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_lookup_elem/
pub unsafe fn raw_map_lookup_elem(map: *mut c_void, key: *const c_void) -> *const c_void {
    let map = Arc::from_raw(map as *const BpfMap);
    let key_size = map.key_size();
    let key = core::slice::from_raw_parts(key as *const u8, key_size);
    let value = map_lookup_elem(&map, key);
    info!("<raw_map_lookup_elem>: {:x?}", value);
    // warning: We need to keep the map alive, so we don't drop it here.
    Arc::into_raw(map);
    match value {
        Ok(Some(value)) => value as *const c_void,
        _ => core::ptr::null_mut(),
    }
}

pub fn map_lookup_elem(map: &Arc<BpfMap>, key: &[u8]) -> Result<Option<*const u8>> {
    let binding = map.inner_map().lock();
    let key_value = u32::from_ne_bytes(key[0..4].try_into().unwrap());
    info!("<map_lookup_elem> key_value: {:?}", key_value);
    let value = binding.lookup_elem(key);
    match value {
        Ok(Some(value)) => Ok(Some(value.as_ptr())),
        _ => Ok(None),
    }
}

/// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_perf_event_output/
///
/// See https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
pub unsafe fn raw_perf_event_output(
    ctx: *mut c_void,
    map: *mut c_void,
    flags: u64,
    data: *mut c_void,
    size: u64,
) -> u64 {
    info!("<raw_perf_event_output>: {:x?}", data);
    let map = Arc::from_raw(map as *const BpfMap);
    let data = core::slice::from_raw_parts(data as *const u8, size as usize);
    let res = perf_event_output(ctx, &map, flags, data);
    // warning: We need to keep the map alive, so we don't drop it here.
    Arc::into_raw(map);
    match res {
        Ok(_) => 0,
        _ => -1i64 as u64,
    }
}

/// See https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_PERF_EVENT_ARRAY/
pub fn perf_event_output(
    ctx: *mut c_void,
    map: &Arc<BpfMap>,
    flags: u64,
    data: &[u8],
) -> Result<()> {
    let binding = map.inner_map().lock();
    let index = flags as u32;
    let flags = (flags >> 32) as u32;
    let key = if index == BPF_F_CURRENT_CPU as _ {
        let cpu_id = PerCpuInfoImpl::cpu_id();
        cpu_id
    } else {
        index
    };
    let fd = binding.lookup_elem(&key.to_ne_bytes()).unwrap().unwrap();
    let fd = u32::from_ne_bytes(fd.try_into().unwrap());
    info!(
        "<perf_event_output>: flags: {:x?}, index: {:x?}, fd: {:x?}",
        flags, index, fd
    );
    crate::perf::perf_event_output(ctx, fd as usize, flags, data)?;
    Ok(())
}

pub static BPF_HELPER_FUN_SET: Lazy<BTreeMap<u32, RawBPFHelperFn>> = Lazy::new(|| unsafe {
    let mut map = BTreeMap::new();
    map.insert(1, define_func!(raw_map_lookup_elem));
    map.insert(25, define_func!(raw_perf_event_output));
    map
});
