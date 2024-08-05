use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
};
use core::{
    ffi::CStr,
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::atomic::AtomicUsize,
};

use aya_obj::generated::{bpf_attr, bpf_map_type};
use downcast_rs::{impl_downcast, DowncastSync};
use log::info;
use spin::Mutex;

use crate::{
    bpf::map::array_map::*, error::KError, get_file, insert_file, KFile, PerCpuInfoImpl, Result, ID,
};

mod array_map;

#[derive(Debug, Clone)]
pub struct BpfMapMeta {
    pub map_type: bpf_map_type,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub map_name: String,
}

impl From<&bpf_attr> for BpfMapMeta {
    fn from(value: &bpf_attr) -> Self {
        let u = unsafe { &value.__bindgen_anon_1 };
        let map_name_slice = unsafe {
            core::slice::from_raw_parts(u.map_name.as_ptr() as *const u8, u.map_name.len())
        };
        let map_name = CStr::from_bytes_until_nul(map_name_slice)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let map_type = unsafe { core::mem::transmute::<u32, bpf_map_type>(u.map_type) };
        BpfMapMeta {
            map_type,
            key_size: u.key_size,
            value_size: u.value_size,
            max_entries: u.max_entries,
            map_flags: u.map_flags,
            map_name,
        }
    }
}

#[derive(Debug)]
pub struct BpfMap {
    inner_map: Mutex<Box<dyn BpfMapCommonOps>>,
    meta: BpfMapMeta,
}

impl BpfMap {
    pub fn new(map: Box<dyn BpfMapCommonOps>, meta: BpfMapMeta) -> Self {
        BpfMap {
            inner_map: Mutex::new(map),
            meta,
        }
    }

    pub fn inner_map(&self) -> &Mutex<Box<dyn BpfMapCommonOps>> {
        &self.inner_map
    }

    pub fn key_size(&self) -> usize {
        self.meta.key_size as usize
    }

    pub fn value_size(&self) -> usize {
        self.meta.value_size as usize
    }
}

impl KFile for BpfMap {
    fn type_name(&self) -> &'static str {
        "BpfMap"
    }
    fn readable(&self) -> bool {
        true
    }
}

pub trait BpfMapCommonOps: Send + Sync + Debug + DowncastSync {
    /// Lookup an element in the map.
    ///
    /// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_lookup_elem/
    fn lookup_elem(&self, key: &[u8]) -> Result<Option<&[u8]>> {
        panic!("lookup_elem not implemented")
    }
    /// Update an element in the map.
    ///
    /// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_update_elem/
    fn update_elem(&mut self, key: &[u8], value: &[u8], flags: u64) -> Result<()> {
        panic!("update_elem not implemented")
    }
    /// Delete an element from the map.
    ///
    /// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_delete_elem/
    fn delete_elem(&mut self, key: &[u8]) -> Result<()> {
        panic!("delete_elem not implemented")
    }
    /// For each element in map, call callback_fn function with map,
    /// callback_ctx and other map-specific parameters.
    ///
    /// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_for_each_map_elem/
    fn for_each_elem(&mut self, cb: BpfCallBackFn, ctx: &[u8], flags: u64) -> Result<u32> {
        panic!("for_each_elem not implemented")
    }

    /// Get the next key in the map.
    ///
    /// Called from syscall
    fn get_next_key(&self, key: &[u8], next_key: &mut [u8]) -> Result<i32> {
        panic!("get_next_key not implemented")
    }

    /// Freeze the map.
    ///
    /// It's useful for .rodata maps.
    fn freeze(&self) -> Result<()> {
        panic!("freeze not implemented")
    }

    /// Get the first value pointer.
    fn first_value_ptr(&self) -> *const u8 {
        panic!("value_ptr not implemented")
    }
}
impl_downcast!(sync BpfMapCommonOps);

type BpfCallBackFn = fn(key: &[u8], value: &[u8], ctx: &[u8]) -> i32;

#[derive(Debug)]
pub struct BpfMapUpdateArg {
    pub map_fd: u32,
    pub key: u64,
    pub value: u64,
    pub flags: u64,
}

impl From<&bpf_attr> for BpfMapUpdateArg {
    fn from(value: &bpf_attr) -> Self {
        unsafe {
            let u = unsafe { &value.__bindgen_anon_2 };
            BpfMapUpdateArg {
                map_fd: u.map_fd,
                key: u.key,
                value: u.__bindgen_anon_1.value,
                flags: u.flags,
            }
        }
    }
}

pub fn bpf_map_create(attr: &bpf_attr) -> Result<i32> {
    let map_meta = BpfMapMeta::from(attr);
    info!("The map attr is {:#?}", map_meta);
    let map: Box<dyn BpfMapCommonOps> = match map_meta.map_type {
        bpf_map_type::BPF_MAP_TYPE_ARRAY => {
            let array_map = ArrayMap::try_from(&map_meta)?;
            Box::new(array_map)
        }
        bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY => {
            let per_cpu_array_map = PerCpuArrayMap::<PerCpuInfoImpl>::try_from(&map_meta)?;
            Box::new(per_cpu_array_map)
        }
        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY => {
            let perf_event_array_map =
                PerfEventArrayMap::<PerCpuInfoImpl>::try_from(&map_meta).unwrap();
            Box::new(perf_event_array_map)
        }
        _ => {
            unimplemented!("bpf map type {:?} not implemented", map_meta.map_type)
        }
    };
    let bpf_map = BpfMap::new(map, map_meta);
    let id = insert_file(Arc::new(bpf_map));
    info!("create map with fd: [{}]", id);
    Ok(id as _)
}

pub fn bpf_map_update_elem(attr: &bpf_attr) -> Result<i32> {
    let arg = BpfMapUpdateArg::from(attr);
    info!("<bpf_map_update_elem>: {:#x?}", arg);
    let map = get_file(arg.map_fd as usize)
        .unwrap()
        .downcast_arc::<BpfMap>()
        .map_err(|_| KError::KInvalid)
        .unwrap();
    let meta = &map.meta;
    let key_size = meta.key_size as usize;
    let value_size = meta.value_size as usize;
    let (key, value) = unsafe {
        (
            core::slice::from_raw_parts(arg.key as *const u8, key_size),
            core::slice::from_raw_parts(arg.value as *const u8, value_size),
        )
    };
    map.inner_map
        .lock()
        .update_elem(key, value, arg.flags)
        .unwrap();
    Ok(0)
}

pub fn bpf_map_freeze(attr: &bpf_attr) -> Result<i32> {
    let arg = BpfMapUpdateArg::from(attr);
    let map_fd = arg.map_fd;
    info!("<bpf_map_freeze>: map_fd: {:}", map_fd);
    let map = get_file(map_fd as usize)
        .unwrap()
        .downcast_arc::<BpfMap>()
        .map_err(|_| KError::KInvalid)
        .unwrap();
    map.inner_map.lock().freeze()?;
    Ok(0)
}
