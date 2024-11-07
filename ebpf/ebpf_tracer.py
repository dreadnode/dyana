#!/usr/bin/env python3
from bcc import BPF
import json
import sys
import time
import os
import signal
import psutil
from collections import defaultdict

# BPF program to trace syscalls and Python execution
bpf_text = """
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
TRACEPOINT_PROBE(sched, sched_process_exec) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Track Python processes and their children
    if (memcmp(comm, "python", 6) == 0) {
        processes.update(&pid, &pid);
        bpf_trace_printk("Tracking Python process %d\\n", pid);
    }

    return 0;
}

// Track process exit
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (processes.delete(&pid)) {
        bpf_trace_printk("Process %d exited\\n", pid);
    }
    return 0;
}

// Trace syscall entry
RAW_TRACEPOINT_PROBE(sys_enter) {
    struct syscall_event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if we're tracking this process
    u32 *exists = processes.lookup(&pid);
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

    bpf_probe_read(&event.arg0, sizeof(event.arg0), &regs->regs[0]);
    bpf_probe_read(&event.arg1, sizeof(event.arg1), &regs->regs[1]);
    bpf_probe_read(&event.arg2, sizeof(event.arg2), &regs->regs[2]);

    // Special handling for file-related syscalls
    if (event.syscall_id == 257 || // openat
        event.syscall_id == 256 || // open
        event.syscall_id == 322) { // execve
        bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)event.arg1);
    }

    syscall_events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// Trace syscall exit
RAW_TRACEPOINT_PROBE(sys_exit) {
    struct syscall_event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if we're tracking this process
    u32 *exists = processes.lookup(&pid);
    if (!exists) {
        return 0;
    }

    event.pid = pid;
    event.tid = bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.syscall_id = ctx->args[1];
    event.ret = ctx->args[0];
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    syscall_events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}
"""

class PythonTracer:
    def __init__(self):
        try:
            self.bpf = BPF(text=bpf_text, debug=4)
            self.events = defaultdict(list)
            self.memory_stats = defaultdict(list)
            self.start_time = time.time()
            print("BPF program loaded successfully")
        except Exception as e:
            print(f"Failed to initialize BPF: {str(e)}")
            raise

    def _process_event(self, cpu, data, size):
        try:
            event = self.bpf["syscall_events"].event(data)
            event_dict = {
                "timestamp": event.timestamp,
                "pid": event.pid,
                "tid": event.tid,
                "comm": event.comm.decode('utf-8', errors='replace'),
                "syscall_id": event.syscall_id,
                "args": [event.arg0, event.arg1, event.arg2],
                "return_value": event.ret,
                "filename": event.filename.decode('utf-8', errors='replace') if hasattr(event, 'filename') else None
            }
            self.events[event.pid].append(event_dict)
            print(f"Captured syscall {event.syscall_id} from PID {event.pid}")
        except Exception as e:
            print(f"Error processing event: {str(e)}")

    def _get_process_memory(self, pid):
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            return {
                'rss': memory_info.rss / 1024,  # Resident Set Size in KB
                'vms': memory_info.vms / 1024,  # Virtual Memory Size in KB
                'shared': getattr(memory_info, 'shared', 0) / 1024  # Shared memory in KB
            }
        except Exception as e:
            print(f"Error getting memory info for PID {pid}: {str(e)}")
            return {'rss': 0, 'vms': 0, 'shared': 0}

    def run_trace(self, python_script):
        print(f"Starting trace for {python_script}")

        try:
            # Start tracing
            self.bpf["syscall_events"].open_ring_buffer(self._process_event)

            # Execute Python script
            print("Launching Python process...")
            python_process = os.spawnlp(
                os.P_NOWAIT, "python3", "python3", python_script)
            print(f"Started process with PID: {python_process}")

            try:
                while True:
                    try:
                        # Poll for events
                        self.bpf.ring_buffer_poll()

                        # Track memory usage
                        mem_usage = self._get_process_memory(python_process)
                        self.memory_stats[python_process].append({
                            'timestamp': time.time() - self.start_time,
                            'memory': mem_usage
                        })

                        # Check if process is still running
                        os.kill(python_process, 0)
                        time.sleep(0.1)  # Prevent CPU spinning

                    except OSError as e:
                        print(f"Process {python_process} finished: {str(e)}")
                        break
                    except KeyboardInterrupt:
                        print("Received interrupt signal")
                        break

            finally:
                # Clean up
                try:
                    os.kill(python_process, signal.SIGTERM)
                except:
                    pass

            # Process results
            return self._generate_trace_data(python_script)

        except Exception as e:
            print(f"Error during tracing: {str(e)}")
            raise

    def _generate_trace_data(self, python_script):
        trace_data = {
            "metadata": {
                "script": python_script,
                "duration": time.time() - self.start_time,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "processes": {}
        }

        for pid, events in self.events.items():
            memory_data = self.memory_stats.get(int(pid), [])

            # Calculate statistics
            syscall_summary = self._summarize_syscalls(events)
            file_operations = self._summarize_file_operations(events)

            trace_data["processes"][str(pid)] = {
                "events": events,
                "event_count": len(events),
                "syscall_summary": syscall_summary,
                "file_operations": file_operations,
                "memory_profile": memory_data,
                "peak_memory": {
                    'rss': max([m['memory']['rss'] for m in memory_data], default=0),
                    'vms': max([m['memory']['vms'] for m in memory_data], default=0),
                    'shared': max([m['memory']['shared'] for m in memory_data], default=0)
                }
            }

        return trace_data

    def _summarize_syscalls(self, events):
        syscall_counts = defaultdict(int)
        for event in events:
            syscall_counts[event["syscall_id"]] += 1
        return dict(syscall_counts)

    def _summarize_file_operations(self, events):
        file_ops = defaultdict(list)
        for event in events:
            if event.get('filename'):
                file_ops[event['syscall_id']].append({
                    'filename': event['filename'],
                    'timestamp': event['timestamp'],
                    'result': event['return_value']
                })
        return dict(file_ops)

def main():
    if len(sys.argv) != 2:
        print("Usage: %s <python_script>" % sys.argv[0])
        sys.exit(1)

    try:
        print("Initializing eBPF tracer...")
        tracer = PythonTracer()

        print(f"Starting trace of {sys.argv[1]}...")
        trace_data = tracer.run_trace(sys.argv[1])

        # Save results
        output_file = "trace_results.json"
        with open(output_file, "w") as f:
            json.dump(trace_data, indent=2, fp=f)

        print(f"\nTrace completed. Results saved to {output_file}")
        print("\nSummary:")
        print("--------")
        for pid, data in trace_data["processes"].items():
            print(f"PID {pid}:")
            print(f"  Total syscalls: {data['event_count']}")
            print(f"  Peak RSS: {data['peak_memory']['rss']:.2f} KB")
            print(f"  Unique syscalls: {len(data['syscall_summary'])}")
            print(f"  File operations: {len(data['file_operations'])}")

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()