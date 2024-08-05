use core::ffi::{c_int, c_uint, c_void};

use aya_obj::generated::{bpf_attr, perf_event_attr};
use libc::size_t;
pub use libc::{
    off_t, pid_t, rlim_t, rlimit, EINVAL, ENOENT, ENOSPC, MAP_FAILED, MAP_SHARED, PROT_READ,
    PROT_WRITE, RLIMIT_MEMLOCK, RLIM_INFINITY,
};

extern "C" {
    pub fn bpf(cmd: c_int, attr: *mut bpf_attr, size: u32) -> c_int;
    pub fn fcntl(fd: c_int, cmd: c_int, val: c_int) -> c_int;
    pub fn getrlimit(resource: c_uint, rlim: *mut libc::rlimit) -> c_int;
    pub fn close(fd: c_int) -> c_int;
    pub fn ioctl(fd: c_int, request: c_int, arg: c_int) -> c_int;
    pub fn perf_event_open(
        attr: *const perf_event_attr,
        pid: libc::pid_t,
        cpu: c_int,
        group_fd: c_int,
        flags: c_uint,
    ) -> c_int;

    pub fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void;
    pub fn munmap(addr: *mut c_void, len: size_t) -> c_int;

}
