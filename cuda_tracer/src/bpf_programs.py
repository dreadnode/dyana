BPF_CUDA_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Structure to track CUDA API calls
struct cuda_event_t {
    u32 pid;
    u64 timestamp;
    u64 duration;
    char function[64];
    u64 memory_size;
    int status;
};

BPF_RINGBUF_OUTPUT(cuda_events, 1 << 13);
BPF_HASH(cuda_start, u32, u64);

// Trace CUDA driver API entry
TRACEPOINT_PROBE(cuda_driver, function_entry) {
    struct cuda_event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();

    event.pid = pid;
    event.timestamp = ts;
    bpf_probe_read_str(event.function, sizeof(event.function), args->function_name);

    cuda_start.update(&pid, &ts);
    return 0;
}

// Trace CUDA driver API exit
TRACEPOINT_PROBE(cuda_driver, function_exit) {
    struct cuda_event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start_ts = cuda_start.lookup(&pid);

    if (start_ts != NULL) {
        event.pid = pid;
        event.timestamp = *start_ts;
        event.duration = bpf_ktime_get_ns() - *start_ts;
        event.status = args->status;
        bpf_probe_read_str(event.function, sizeof(event.function), args->function_name);

        cuda_events.ringbuf_output(&event, sizeof(event), 0);
        cuda_start.delete(&pid);
    }
    return 0;
}

// Memory allocation tracking
TRACEPOINT_PROBE(cuda_driver, memory_alloc) {
    struct cuda_event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    event.pid = pid;
    event.timestamp = bpf_ktime_get_ns();
    event.memory_size = args->size;
    bpf_probe_read_str(event.function, sizeof(event.function), "cuMemAlloc");

    cuda_events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// Memory free tracking
TRACEPOINT_PROBE(cuda_driver, memory_free) {
    struct cuda_event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    event.pid = pid;
    event.timestamp = bpf_ktime_get_ns();
    bpf_probe_read_str(event.function, sizeof(event.function), "cuMemFree");

    cuda_events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}
"""
