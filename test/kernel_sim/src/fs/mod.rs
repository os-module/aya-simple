mod mmap;

use core::ffi::{c_int, c_longlong, c_uint};

use aya_obj::generated::{
    AYA_PERF_EVENT_IOC_DISABLE, AYA_PERF_EVENT_IOC_ENABLE, AYA_PERF_EVENT_IOC_SET_BPF,
};
use shim_std::libc::rlimit;

use crate::{
    error::KError,
    fs::mmap::{TmpMMapFlag, TmpMMapProt},
};

// #[no_mangle]
// pub extern "C" fn fcntl(fd: c_int, cmd: c_int, val: c_int) -> c_int {
//     info!("fcntl: fd: {}, cmd: {}, val: {}", fd, cmd, val);
//     unimplemented!("This need call to SYS_fcntl")
// }
#[no_mangle]
pub extern "C" fn mmap(
    addr: *mut core::ffi::c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> *mut core::ffi::c_void {
    let prot = TmpMMapProt::from_bits_truncate(prot as u32);
    let flags = TmpMMapFlag::from_bits_truncate(flags as u32);
    let res = mmap::mmap(
        addr as usize,
        len,
        prot,
        flags,
        fd as usize,
        offset as usize,
    );
    match res {
        Ok(res) => res as *mut core::ffi::c_void,
        Err(e) => {
            error!("mmap error: {:?}", e);
            core::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn getrlimit(resource: c_uint, rlim: *mut rlimit) -> c_int {
    unimplemented!("This need call to SYS_getrlimit")
}

#[no_mangle]
pub extern "C" fn close(fd: c_int) -> c_int {
    let res1 = crate::remove_file(fd as _);
    if res1.is_err() {
        error!("The fd {} is not found", fd);
        return -1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn ioctl(fd: c_int, request: c_int, arg: usize) -> c_longlong {
    warn!("ioctl: fd: {}, request: {}, arg: {}", fd, request, arg);
    let fd = fd as usize;
    let res = match request {
        crate::PERF_EVENT_IOC_ENABLE
        | crate::PERF_EVENT_IOC_DISABLE
        | crate::PERF_EVENT_IOC_SET_BPF => crate::perf::perf_event_ioctl(fd, request, arg),
        _ => unimplemented!("ioctl request: {}", request),
    };
    match res {
        Ok(_) => 0,
        Err(e) => e as i64,
    }
}
