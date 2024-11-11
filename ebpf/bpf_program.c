#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/syscalls.h>

// Data structure to store syscall info
struct syscall_event_t {
    u32 pid;
    u32 tid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    u64 syscall_id;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 ret;
    char filename[256];
};

// Ringbuffer for events
BPF_RINGBUF_OUTPUT(syscall_events, 1 << 13);  // 8KB = 8192 bytes

// Hash to track process info
BPF_HASH(processes, u32, u32);

// Track process creation
__attribute__((section(".bpf.fn.raw_tracepoint__sched_process_exec")))
RAW_TRACEPOINT_PROBE(sched_process_exec) {
    u32 pid;
    u32 one = 1;
    char comm[TASK_COMM_LEN];

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));

    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (comm[i] != "python"[i]) {
            return 0;
        }
    }

    bpf_map_update_elem(&processes, &pid, &one, BPF_ANY);
    return 0;
}

// Trace syscall entry
__attribute__((section(".bpf.fn.raw_tracepoint__sys_enter")))
RAW_TRACEPOINT_PROBE(sys_enter) {
    struct syscall_event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if we're tracking this process
    u32 *exists = bpf_map_lookup_elem(&processes, &pid);
    if (!exists) {
        return 0;
    }

    event.pid = pid;
    event.tid = bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();

    // Get syscall ID and args from context
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    event.syscall_id = ctx->args[1];

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Read args for important syscalls
    if (event.syscall_id == 257 || // openat
        event.syscall_id == 256 || // open
        event.syscall_id == 322 || // execve
        event.syscall_id == 59  || // execve
        event.syscall_id == 56  || // clone
        event.syscall_id == 57  || // fork
        event.syscall_id == 58) {  // vfork

        bpf_probe_read(&event.arg0, sizeof(event.arg0), &regs->regs[0]);
        bpf_probe_read(&event.arg1, sizeof(event.arg1), &regs->regs[1]);
        bpf_probe_read(&event.arg2, sizeof(event.arg2), &regs->regs[2]);

        // Special handling for file-related syscalls
        if (event.syscall_id == 257 || event.syscall_id == 256) {
            bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)event.arg1);
        }
    } else {
        // For other syscalls, just get basic info
        bpf_probe_read(&event.arg0, sizeof(event.arg0), &regs->regs[0]);
    }

    bpf_ringbuf_output(&syscall_events, &event, sizeof(event), 0);
    return 0;
}

// Trace syscall exit
__attribute__((section(".bpf.fn.raw_tracepoint__sys_exit")))
RAW_TRACEPOINT_PROBE(sys_exit) {
    struct syscall_event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if we're tracking this process
    u32 *exists = bpf_map_lookup_elem(&processes, &pid);
    if (!exists) {
        return 0;
    }

    event.pid = pid;
    event.tid = bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.syscall_id = ctx->args[1];
    event.ret = ctx->args[0];
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_ringbuf_output(&syscall_events, &event, sizeof(event), 0);
    return 0;
}