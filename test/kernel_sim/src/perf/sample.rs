use int_enum::IntEnum;

#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, IntEnum)]
#[allow(non_camel_case_types)]
pub enum PerfSwIds {
    PERF_COUNT_SW_CPU_CLOCK = 0,
    PERF_COUNT_SW_TASK_CLOCK = 1,
    PERF_COUNT_SW_PAGE_FAULTS = 2,
    PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
    PERF_COUNT_SW_CPU_MIGRATIONS = 4,
    PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
    PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
    PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
    PERF_COUNT_SW_EMULATION_FAULTS = 8,
    PERF_COUNT_SW_DUMMY = 9,
    PERF_COUNT_SW_BPF_OUTPUT = 10,
    PERF_COUNT_SW_CGROUP_SWITCHES = 11,
    PERF_COUNT_SW_MAX = 12,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, IntEnum)]
#[allow(non_camel_case_types)]
pub enum PerfEventType {
    PERF_RECORD_MMAP = 1,
    PERF_RECORD_LOST = 2,
    PERF_RECORD_COMM = 3,
    PERF_RECORD_EXIT = 4,
    PERF_RECORD_THROTTLE = 5,
    PERF_RECORD_UNTHROTTLE = 6,
    PERF_RECORD_FORK = 7,
    PERF_RECORD_READ = 8,
    PERF_RECORD_SAMPLE = 9,
    PERF_RECORD_MMAP2 = 10,
    PERF_RECORD_AUX = 11,
    PERF_RECORD_ITRACE_START = 12,
    PERF_RECORD_LOST_SAMPLES = 13,
    PERF_RECORD_SWITCH = 14,
    PERF_RECORD_SWITCH_CPU_WIDE = 15,
    PERF_RECORD_NAMESPACES = 16,
    PERF_RECORD_KSYMBOL = 17,
    PERF_RECORD_BPF_EVENT = 18,
    PERF_RECORD_CGROUP = 19,
    PERF_RECORD_TEXT_POKE = 20,
    PERF_RECORD_AUX_OUTPUT_HW_ID = 21,
    PERF_RECORD_MAX = 22,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, IntEnum)]
#[allow(non_camel_case_types)]
pub enum PerfEventSampleFormat {
    PERF_SAMPLE_IP = 1,
    PERF_SAMPLE_TID = 2,
    PERF_SAMPLE_TIME = 4,
    PERF_SAMPLE_ADDR = 8,
    PERF_SAMPLE_READ = 16,
    PERF_SAMPLE_CALLCHAIN = 32,
    PERF_SAMPLE_ID = 64,
    PERF_SAMPLE_CPU = 128,
    PERF_SAMPLE_PERIOD = 256,
    PERF_SAMPLE_STREAM_ID = 512,
    PERF_SAMPLE_RAW = 1024,
    PERF_SAMPLE_BRANCH_STACK = 2048,
    PERF_SAMPLE_REGS_USER = 4096,
    PERF_SAMPLE_STACK_USER = 8192,
    PERF_SAMPLE_WEIGHT = 16384,
    PERF_SAMPLE_DATA_SRC = 32768,
    PERF_SAMPLE_IDENTIFIER = 65536,
    PERF_SAMPLE_TRANSACTION = 131072,
    PERF_SAMPLE_REGS_INTR = 262144,
    PERF_SAMPLE_PHYS_ADDR = 524288,
    PERF_SAMPLE_AUX = 1048576,
    PERF_SAMPLE_CGROUP = 2097152,
    PERF_SAMPLE_DATA_PAGE_SIZE = 4194304,
    PERF_SAMPLE_CODE_PAGE_SIZE = 8388608,
    PERF_SAMPLE_WEIGHT_STRUCT = 16777216,
    PERF_SAMPLE_MAX = 33554432,
}

#[repr(u32)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, IntEnum)]
pub enum PerfTypeId {
    PERF_TYPE_HARDWARE = 0,
    PERF_TYPE_SOFTWARE = 1,
    PERF_TYPE_TRACEPOINT = 2,
    PERF_TYPE_HW_CACHE = 3,
    PERF_TYPE_RAW = 4,
    PERF_TYPE_BREAKPOINT = 5,
    PERF_TYPE_MAX = 6,
}
