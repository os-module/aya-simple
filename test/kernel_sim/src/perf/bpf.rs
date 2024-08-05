use alloc::{vec, vec::Vec};
use core::fmt::Debug;

use aya_obj::generated::{perf_event_header, perf_event_mmap_page};
use spin::Mutex;

use crate::{
    perf::{sample::PerfEventType, PerfEventOps, PerfProbeArgs},
    Result,
};
const PAGE_SIZE: usize = 4096;
#[derive(Debug)]
pub struct BpfPerfEvent {
    args: PerfProbeArgs,
    data: Mutex<BpfPerfEventData>,
}

#[derive(Debug)]
pub struct BpfPerfEventData {
    enabled: bool,
    mmap_page: Page,
    offset: usize,
}

// #[repr(C)]
// #[derive(Debug, Copy, Clone)]
// pub struct perf_event_header {
//     pub type_: __u32,
//     pub misc: __u16,
//     pub size: __u16,
// }
/// The event type in our particular use case will be `PERF_RECORD_SAMPLE` or `PERF_RECORD_LOST`.
/// `PERF_RECORD_SAMPLE` indicating that there is an actual sample after this header.
/// And `PERF_RECORD_LOST` indicating that there is a record lost header following the perf event header.
#[repr(C)]
#[derive(Debug)]
struct LostSamples {
    header: perf_event_header,
    id: u64,
    count: u64,
}

impl LostSamples {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    fn copy_to_slice(&self, slice: &mut [u8]) {
        let bytes = self.as_bytes();
        slice[..bytes.len()].copy_from_slice(bytes);
    }
}

#[repr(C)]
#[derive(Debug)]
struct Sample {
    header: perf_event_header,
    size: u32,
}

impl Sample {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct PerfSample<'a> {
    s_hdr: Sample,
    value: &'a [u8],
}

impl<'a> PerfSample<'a> {
    fn calculate_size(value_size: usize) -> usize {
        core::mem::size_of::<Sample>() + value_size
    }

    fn copy_to_slice(&self, slice: &mut [u8]) {
        let sample_hdr = self.s_hdr.as_bytes();
        slice[..sample_hdr.len()].copy_from_slice(sample_hdr);
        let end = sample_hdr.len() + self.value.len();
        slice[sample_hdr.len()..end].copy_from_slice(self.value);
    }
}

#[derive(Debug)]
pub struct Page {
    size: usize,
    ptr: usize,
    data_region_size: usize,
    lost: usize,
}

impl Page {
    pub fn empty() -> Self {
        Page {
            ptr: 0,
            size: 0,
            data_region_size: 0,
            lost: 0,
        }
    }

    pub fn alloc(size: usize) -> Self {
        assert_eq!(size % PAGE_SIZE, 0);
        assert!(size / PAGE_SIZE >= 2);
        let ptr = unsafe {
            alloc::alloc::alloc(alloc::alloc::Layout::from_size_align(size, PAGE_SIZE).unwrap())
        };
        // The first page will be filled with perf_event_mmap_page
        unsafe {
            let perf_event_mmap_page = &mut *(ptr as *mut perf_event_mmap_page);
            perf_event_mmap_page.data_offset = PAGE_SIZE as u64;
            perf_event_mmap_page.data_size = (size - PAGE_SIZE) as u64;
            // user will read sample or lost record from data_tail
            perf_event_mmap_page.data_tail = 0;
            // kernel will write sample or lost record from data_head
            perf_event_mmap_page.data_head = 0;
            // It is a ring buffer.
        }
        Page {
            ptr: ptr as usize,
            size,
            data_region_size: size - PAGE_SIZE,
            lost: 0,
        }
    }

    fn can_write(&self, data_size: usize, data_tail: usize, data_head: usize) -> bool {
        if (data_head + 1) % self.data_region_size == data_tail {
            // The buffer is full
            return false;
        }
        let capacity = if data_head >= data_tail {
            self.data_region_size - data_head + data_tail
        } else {
            data_tail - data_head
        };
        data_size <= capacity
    }

    pub fn write_event(&mut self, data: &[u8]) -> Result<()> {
        let data_tail = unsafe { &mut (*(self.ptr as *mut perf_event_mmap_page)).data_tail };
        let data_head = unsafe { &mut (*(self.ptr as *mut perf_event_mmap_page)).data_head };
        // data_tail..data_head is the region that can be written
        // check if there is enough space to write the event
        let sample_size = PerfSample::calculate_size(data.len());

        let can_write_sample =
            self.can_write(sample_size, *data_tail as usize, *data_head as usize);
        error!(
            "can_write_sample: {}, data_tail: {}, data_head: {}, data.len(): {}, region_size: {}",
            can_write_sample,
            *data_tail,
            *data_head,
            data.len(),
            self.data_region_size
        );
        if !can_write_sample {
            //we need record it to the lost record
            self.lost += 1;
            error!(
                "Lost record: {}, data_tail: {}, data_head: {}",
                self.lost, *data_tail, *data_head
            );
            Ok(())
        } else {
            // we can write the sample to the page
            // If the lost record is not zero, we need to write the lost record first.
            let can_write_lost_record = self.can_write(
                core::mem::size_of::<LostSamples>(),
                *data_tail as usize,
                *data_head as usize,
            );
            if self.lost > 0 && can_write_lost_record {
                let new_data_head = self.write_lost(*data_head as usize)?;
                *data_head = new_data_head as u64;
                info!(
                    "Write lost record: {}, data_tail: {}, new_data_head: {}",
                    self.lost, *data_tail, *data_head
                );
                self.lost = 0;
                self.write_event(data)
            } else {
                let new_data_head = self.write_sample(data, *data_head as usize)?;
                *data_head = new_data_head as u64;
                info!(
                    "Write sample record, data_tail: {}, new_data_head: {}",
                    *data_tail, *data_head
                );
                Ok(())
            }
        }
    }

    /// Write any data to the page.
    ///
    /// Return the new data_head
    fn write_any(&mut self, data: &[u8], data_head: usize) -> Result<usize> {
        let data_region_len = self.data_region_size;
        let data_region = self.as_mut_slice()[PAGE_SIZE..].as_mut();
        let data_len = data.len();
        let end = (data_head + data_len) % data_region_len;
        let start = data_head;
        if start < end {
            data_region[start..end].copy_from_slice(data);
        } else {
            let first_len = data_region_len - start;
            data_region[start..start + first_len].copy_from_slice(&data[..first_len]);
            data_region[0..end].copy_from_slice(&data[first_len..]);
        }
        Ok(end)
    }

    /// Write a sample to the page.
    fn write_sample(&mut self, data: &[u8], data_head: usize) -> Result<usize> {
        let perf_sample = PerfSample {
            s_hdr: Sample {
                header: perf_event_header {
                    type_: PerfEventType::PERF_RECORD_SAMPLE as u32,
                    misc: 0,
                    size: core::mem::size_of::<Sample>() as u16 + data.len() as u16,
                },
                size: data.len() as u32,
            },
            value: data,
        };
        let new_head = self.write_any(perf_sample.s_hdr.as_bytes(), data_head)?;
        self.write_any(perf_sample.value, new_head)
    }

    /// Write a lost record to the page.
    ///
    /// Return the new data_head
    fn write_lost(&mut self, data_head: usize) -> Result<usize> {
        let lost = LostSamples {
            header: perf_event_header {
                type_: PerfEventType::PERF_RECORD_LOST as u32,
                misc: 0,
                size: core::mem::size_of::<LostSamples>() as u16,
            },
            id: 0,
            count: self.lost as u64,
        };
        self.write_any(lost.as_bytes(), data_head)
    }

    pub fn readable(&self) -> bool {
        let data_tail = unsafe { &(*(self.ptr as *mut perf_event_mmap_page)).data_tail };
        let data_head = unsafe { &(*(self.ptr as *mut perf_event_mmap_page)).data_head };
        data_tail != data_head
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.size) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.size) }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        if self.ptr != 0 {
            unsafe {
                alloc::alloc::dealloc(
                    self.ptr as *mut u8,
                    alloc::alloc::Layout::from_size_align(self.size, PAGE_SIZE).unwrap(),
                )
            };
        }
    }
}

impl BpfPerfEvent {
    pub fn new(args: PerfProbeArgs) -> Self {
        BpfPerfEvent {
            args,
            data: Mutex::new(BpfPerfEventData {
                enabled: false,
                mmap_page: Page::empty(),
                offset: 0,
            }),
        }
    }
    pub fn alloc_mmap(&self, len: usize, offset: usize) -> crate::Result<usize> {
        let mut data = self.data.lock();
        let mmap_page = Page::alloc(len);
        data.mmap_page = mmap_page;
        data.offset = offset;
        let mmap_page_ptr = data.mmap_page.as_ptr() as usize;
        Ok(mmap_page_ptr)
    }

    pub fn write_event(&self, data: &[u8]) -> Result<()> {
        let mut inner_data = self.data.lock();
        inner_data.mmap_page.write_event(data)
    }
}

impl PerfEventOps for BpfPerfEvent {
    fn enable(&self) -> crate::Result<()> {
        self.data.lock().enabled = true;
        Ok(())
    }
    fn disable(&self) -> crate::Result<()> {
        self.data.lock().enabled = false;
        Ok(())
    }
    fn readable(&self) -> bool {
        // false
        self.data.lock().mmap_page.readable()
    }
}

pub fn perf_event_open_bpf(args: PerfProbeArgs) -> BpfPerfEvent {
    BpfPerfEvent::new(args)
}
