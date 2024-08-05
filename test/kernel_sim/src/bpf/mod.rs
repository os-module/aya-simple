pub mod helper;
pub mod map;
pub mod prog;

use core::ffi::c_int;

use aya_obj::generated::{bpf_attr, bpf_cmd};
pub use helper::BPF_HELPER_FUN_SET;

use crate::bpf::{
    map::{bpf_map_create, bpf_map_freeze, bpf_map_update_elem},
    prog::bpf_prog_load,
};

#[no_mangle]
pub unsafe extern "C" fn bpf(cmd: c_int, attr: *mut bpf_attr, size: u32) -> c_int {
    let cmd = core::mem::transmute::<c_int, bpf_cmd>(cmd);
    let attr = unsafe { &mut *attr };
    normal_bpf(cmd, attr)
}

pub fn normal_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> c_int {
    let res = match cmd {
        bpf_cmd::BPF_MAP_CREATE => bpf_map_create(attr),
        bpf_cmd::BPF_MAP_UPDATE_ELEM => bpf_map_update_elem(attr),
        bpf_cmd::BPF_PROG_LOAD => bpf_prog_load(attr),
        bpf_cmd::BPF_MAP_FREEZE => bpf_map_freeze(attr),
        ty => {
            unimplemented!("bpf cmd {:?} not implemented", ty)
        }
    };
    res.unwrap_or_else(|e| e as i32)
}
