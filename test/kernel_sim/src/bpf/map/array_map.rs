//! BPF_MAP_TYPE_ARRAY and BPF_MAP_TYPE_PERCPU_ARRAY
//!
//!
//! See https://docs.kernel.org/bpf/map_array.html

use alloc::{vec, vec::Vec};
use core::{
    fmt::{Debug, Formatter},
    ops::{Index, IndexMut},
};

use crate::{
    bpf::map::{BpfCallBackFn, BpfMapCommonOps, BpfMapMeta},
    error::KError,
    util::round_up,
    PerCpuInfo,
};

#[derive(Debug)]
pub struct ArrayMap {
    max_entries: u32,
    data: ArrayMapData,
}

struct ArrayMapData {
    elem_size: u32,
    data: Vec<u8>,
}

impl Debug for ArrayMapData {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArrayMapData")
            .field("elem_size", &self.elem_size)
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl ArrayMapData {
    pub fn new(elem_size: u32, max_entries: u32) -> Self {
        debug_assert!(elem_size % 8 == 0);
        let total_size = elem_size * max_entries;
        let data = vec![0; total_size as usize];
        ArrayMapData { elem_size, data }
    }
}

impl Index<u32> for ArrayMapData {
    type Output = [u8];
    fn index(&self, index: u32) -> &Self::Output {
        let start = index * self.elem_size;
        &self.data[start as usize..(start + self.elem_size) as usize]
    }
}

impl IndexMut<u32> for ArrayMapData {
    fn index_mut(&mut self, index: u32) -> &mut Self::Output {
        let start = index * self.elem_size;
        &mut self.data[start as usize..(start + self.elem_size) as usize]
    }
}

impl TryFrom<&BpfMapMeta> for ArrayMap {
    type Error = KError;
    fn try_from(attr: &BpfMapMeta) -> Result<Self, Self::Error> {
        if attr.value_size == 0 || attr.max_entries == 0 || attr.key_size != 4 {
            return Err(KError::KInvalid);
        }
        let elem_size = round_up(attr.value_size as usize, 8);
        let data = ArrayMapData::new(elem_size as u32, attr.max_entries);
        Ok(ArrayMap {
            max_entries: attr.max_entries,
            data,
        })
    }
}

impl BpfMapCommonOps for ArrayMap {
    fn lookup_elem(&self, key: &[u8]) -> crate::Result<Option<&[u8]>> {
        if key.len() != 4 {
            return Err(KError::KInvalid);
        }
        let index = u32::from_ne_bytes(key.try_into().unwrap());
        if index >= self.max_entries {
            return Err(KError::KInvalid);
        }
        let val = self.data.index(index);
        Ok(Some(val))
    }
    fn update_elem(&mut self, key: &[u8], value: &[u8], flags: u64) -> crate::Result<()> {
        if key.len() != 4 {
            return Err(KError::KInvalid);
        }
        let index = u32::from_ne_bytes(key.try_into().unwrap());
        if index >= self.max_entries {
            return Err(KError::KInvalid);
        }
        if value.len() > self.data.elem_size as usize {
            return Err(KError::KInvalid);
        }
        let old_value = self.data.index_mut(index);
        old_value[..value.len()].copy_from_slice(value);
        Ok(())
    }
    fn delete_elem(&mut self, key: &[u8]) -> crate::Result<()> {
        Err(KError::KInvalid)
    }
    fn for_each_elem(&mut self, cb: BpfCallBackFn, ctx: &[u8], flags: u64) -> crate::Result<u32> {
        if flags != 0 {
            return Err(KError::KInvalid);
        }
        let mut total_used = 0;
        for i in 0..self.max_entries {
            let key = i.to_ne_bytes();
            let value = self.data.index(i);
            total_used += 1;
            let res = cb(ctx, &key, value);
            // return value: 0 - continue, 1 - stop and return
            if res != 0 {
                break;
            }
        }
        Ok(total_used)
    }

    fn get_next_key(&self, key: &[u8], next_key: &mut [u8]) -> crate::Result<i32> {
        if key.len() != 4 || next_key.len() != 4 {
            return Err(KError::KInvalid);
        }
        let index = u32::from_ne_bytes(key.try_into().unwrap());
        if index >= self.max_entries {
            return Ok(0);
        }
        if index == self.max_entries - 1 {
            return Err(KError::KENOENT);
        }
        let next_index = index + 1;
        next_key.copy_from_slice(&next_index.to_ne_bytes());
        Ok(0)
    }

    fn freeze(&self) -> crate::Result<()> {
        info!("fake freeze done for ArrayMap");
        Ok(())
    }
    fn first_value_ptr(&self) -> *const u8 {
        self.data.data.as_ptr()
    }
}

pub struct PerCpuArrayMap<T> {
    data: Vec<ArrayMap>,
    _phantom: core::marker::PhantomData<T>,
}

impl<T> Debug for PerCpuArrayMap<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerCpuArrayMap")
            .field("data", &self.data)
            .finish()
    }
}

impl<T: PerCpuInfo> TryFrom<&BpfMapMeta> for PerCpuArrayMap<T> {
    type Error = KError;
    fn try_from(attr: &BpfMapMeta) -> Result<Self, Self::Error> {
        let num_cpus = T::num_cpus();
        let mut data = Vec::with_capacity(num_cpus as usize);
        for i in 0..num_cpus {
            let array_map = ArrayMap::try_from(attr)?;
            data.push(array_map);
        }
        Ok(PerCpuArrayMap {
            data,
            _phantom: core::marker::PhantomData,
        })
    }
}

impl<T: PerCpuInfo> BpfMapCommonOps for PerCpuArrayMap<T> {
    fn lookup_elem(&self, key: &[u8]) -> crate::Result<Option<&[u8]>> {
        let cpu_id = T::cpu_id();
        self.data[cpu_id as usize].lookup_elem(key)
    }
    fn update_elem(&mut self, key: &[u8], value: &[u8], flags: u64) -> crate::Result<()> {
        let cpu_id = T::cpu_id();
        self.data[cpu_id as usize].update_elem(key, value, flags)
    }
    fn delete_elem(&mut self, key: &[u8]) -> crate::Result<()> {
        let cpu_id = T::cpu_id();
        self.data[cpu_id as usize].delete_elem(key)
    }
    fn for_each_elem(&mut self, cb: BpfCallBackFn, ctx: &[u8], flags: u64) -> crate::Result<u32> {
        let cpu_id = T::cpu_id();
        self.data[cpu_id as usize].for_each_elem(cb, ctx, flags)
    }
    fn get_next_key(&self, key: &[u8], next_key: &mut [u8]) -> crate::Result<i32> {
        let cpu_id = T::cpu_id();
        self.data[cpu_id as usize].get_next_key(key, next_key)
    }
    fn first_value_ptr(&self) -> *const u8 {
        let cpu_id = T::cpu_id();
        self.data[cpu_id as usize].first_value_ptr()
    }
}

/// See https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_PERF_EVENT_ARRAY/
pub struct PerfEventArrayMap<T> {
    // The value is the file descriptor of the perf event.
    fds: ArrayMapData,
    _phantom: core::marker::PhantomData<T>,
}

impl<T> Debug for PerfEventArrayMap<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerfEventArrayMap")
            .field("fds", &self.fds)
            .finish()
    }
}

impl<T: PerCpuInfo> TryFrom<&BpfMapMeta> for PerfEventArrayMap<T> {
    type Error = KError;
    fn try_from(attr: &BpfMapMeta) -> Result<Self, Self::Error> {
        let num_cpus = T::num_cpus();
        if attr.key_size != 4 || attr.value_size != 4 || attr.max_entries != num_cpus {
            return Err(KError::KInvalid);
        }
        let fds = ArrayMapData::new(4, num_cpus);
        Ok(PerfEventArrayMap {
            fds,
            _phantom: core::marker::PhantomData,
        })
    }
}

impl<T: PerCpuInfo> BpfMapCommonOps for PerfEventArrayMap<T> {
    fn lookup_elem(&self, key: &[u8]) -> crate::Result<Option<&[u8]>> {
        let cpu_id = u32::from_ne_bytes(key.try_into().unwrap());
        let value = self.fds.index(cpu_id);
        Ok(Some(value))
    }
    fn update_elem(&mut self, key: &[u8], value: &[u8], flags: u64) -> crate::Result<()> {
        assert_eq!(value.len(), 4);
        let cpu_id = u32::from_ne_bytes(key.try_into().unwrap());
        let old_value = self.fds.index_mut(cpu_id);
        old_value.copy_from_slice(value);
        Ok(())
    }
    fn delete_elem(&mut self, key: &[u8]) -> crate::Result<()> {
        let cpu_id = u32::from_ne_bytes(key.try_into().unwrap());
        self.fds.index_mut(cpu_id).copy_from_slice(&[0; 4]);
        Ok(())
    }
    fn for_each_elem(&mut self, cb: BpfCallBackFn, ctx: &[u8], flags: u64) -> crate::Result<u32> {
        let mut total_used = 0;
        for i in 0..T::num_cpus() {
            let key = i.to_ne_bytes();
            let value = self.fds.index(i);
            total_used += 1;
            let res = cb(ctx, &key, &value);
            if res != 0 {
                break;
            }
        }
        Ok(total_used)
    }
    fn first_value_ptr(&self) -> *const u8 {
        self.fds.data.as_ptr()
    }
}
