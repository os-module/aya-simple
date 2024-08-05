#[no_mangle]
pub extern "Rust" fn extern_read_sys_fs_perf_type(pmu: &str) -> Result<u32, &'static str> {
    if pmu == "/sys/bus/event_source/devices/kprobe/type" {
        Ok(6)
    } else {
        panic!(
            "extern_read_sys_fs_perf_type is not implemented yet for {}",
            pmu
        );
    }
}

#[no_mangle]
pub extern "Rust" fn extern_read_sys_fs_perf_ret_probe(pmu: &str) -> Result<u32, &'static str> {
    if pmu == "/sys/bus/event_source/devices/kporbe/format/retprobe" {
        Ok(0)
    } else {
        panic!(
            "extern_read_sys_fs_perf_ret_probe is not implemented yet for {}",
            pmu
        );
    }
}
