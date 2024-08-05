mod fake_func;

use std::{os::fd::AsRawFd, sync::Arc};

use aya::{
    include_bytes_aligned,
    maps::{
        perf::{Events, PerfEventArrayBuffer},
        Map, MapData, PerfEventArray,
    },
    programs::kprobe::KProbe,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use kernel_sim::file_readable;
use log::{error, info};
use rbpf::disassembler;

extern crate kernel_sim;

// #[tokio::main(flavor = "current_thread")]
fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .format_timestamp(None)
        .init();
    // env_logger::init_from_env(env_logger::Env::default().default_filter_or("trace"));

    let mut bpf = Ebpf::load(include_bytes_aligned!("../myapp")).unwrap();

    // create a async task to read the log
    // if let Err(e) = EbpfLogger::init(&mut bpf) {
    //     // This can happen if you remove all log statements from your eBPF program.
    //     warn!("failed to initialize eBPF logger: {}", e);
    // }

    const MAP_NAME: &str = "AYA_LOGS";
    let map = bpf.take_map(MAP_NAME).unwrap();
    let event_buf = bpf_log_init(map);

    let program: &mut KProbe = bpf.program_mut("myapp").unwrap().try_into().unwrap();
    // let code = program.inst().unwrap();
    // info!("code len: {}", code.len());
    //
    // let prog = unsafe { core::slice::from_raw_parts(code.as_ptr() as *const u8, code.len() * 8) };
    // let insn_raw = to_insn_vec(prog);
    // for (index,insn) in disassembler::to_insn_vec(prog).iter().enumerate() {
    //     if insn.desc.starts_with("call"){
    //        warn!("src_reg: {}, imm: {}", insn.src, insn.imm);
    //     }
    //     info!("{}", insn.desc);
    // }

    program.load().unwrap();

    let _kprobe_link_id = program.attach("try_to_wake_up", 0).unwrap();
    // program.detach()

    let work_thread = std::thread::spawn(|| {
        run_kernel_fake_perf();
    });

    let log_thread = std::thread::spawn(|| {
        fake_log_buf_read(event_buf);
    });

    work_thread.join().unwrap();
    log_thread.join().unwrap();

    info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await.unwrap();
    info!("Exiting...");
}

pub fn run_kernel_fake_perf() {
    let mut now = std::time::Instant::now();
    loop {
        let new_now = std::time::Instant::now();
        if new_now.duration_since(now).as_millis() >= 500 {
            kernel_sim::fake_kernel_event_loop();
            now = new_now;
        }
    }
}

pub fn bpf_log_init(map: Map) -> Vec<PerfEventArrayBuffer<MapData>> {
    let mut perf_array: PerfEventArray<_> = PerfEventArray::try_from(map).unwrap();
    // eBPF programs are going to write to the EVENTS perf array, using the id of the CPU they're
    // running on as the array index.
    let mut perf_buffers = Vec::new();
    for cpu_id in online_cpus().unwrap() {
        // this perf buffer will receive events generated on the CPU with id cpu_id
        let buf = perf_array.open(cpu_id, Some(1)).unwrap();
        perf_buffers.push(buf);
    }
    perf_buffers
}

pub fn fake_log_buf_read(mut perf_buffers: Vec<PerfEventArrayBuffer<MapData>>) {
    info!("fake_log_buf_read");
    let logger = log::logger();
    let logger = Arc::new(logger);

    let mut buffers = vec![BytesMut::with_capacity(4096); 10];

    let mut now = std::time::Instant::now();

    loop {
        let new_now = std::time::Instant::now();
        if new_now.duration_since(now).as_secs() > 20 {
            break;
        }
    }

    loop {
        let new_now = std::time::Instant::now();
        // read the perf buffer every 2 seconds
        if new_now.duration_since(now).as_millis() >= 200 {
            for read_buf in perf_buffers.iter_mut() {
                // poll the buffers to know when they have queued events
                if !file_readable(read_buf.as_raw_fd() as usize) {
                    error!("file_readable false");
                    continue;
                }
                let Events { read, lost: _ } = read_buf.read_events(&mut buffers).unwrap();
                error!("read: {}", read);
                // process out_bufs
                for buf in buffers.iter().take(read) {
                    aya_log::log_buf(buf.as_ref(), &*logger).unwrap();
                }
            }
            now = new_now;
        }
    }
}
