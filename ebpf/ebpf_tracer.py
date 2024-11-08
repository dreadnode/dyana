#!/usr/bin/env python3
from bcc import BPF
import json
import sys
import time
import os
import signal
import psutil
from collections import defaultdict

# Syscall categories and their mappings
SYSCALL_CATEGORIES = {
    'file_ops': {
        2: "open",
        3: "close",
        257: "openat",
    },
    'process_ops': {
        38: "clone",
        57: "fork",
        322: "execve",
        93: "exit",
    },
    'memory_ops': {
        9: "mmap",
    },
    'io_ops': {
        0: "read",
        1: "write",
    },
    'system_info': {
        36: "getpid",
        79: "getcwd",
    },
    'synchronization': {
        35: "nanosleep",
    },
    'file_descriptors': {
        32: "dup",
    },
    'filesystem': {
        135: "sysfs",
    },
    'event_handling': {
        215: "epoll_create",
        233: "epoll_ctl",
    }
}

# Flatten categories into SYSCALLS dict while preserving category info
SYSCALLS = {}
SYSCALL_TO_CATEGORY = {}

for category, syscalls in SYSCALL_CATEGORIES.items():
    for syscall_id, syscall_name in syscalls.items():
        SYSCALLS[syscall_id] = syscall_name
        SYSCALL_TO_CATEGORY[syscall_id] = category

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
BPF_HASH(memory_allocs, u32, u64);  // Track memory allocations per PID
BPF_HASH(memory_peaks, u32, u64);   // Track peak memory usage

// Track process creation
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

    processes.update(&pid, &one);
    bpf_trace_printk("Tracking Python process %d\\n", pid);
    return 0;
}

// Track process exit
RAW_TRACEPOINT_PROBE(sched_process_exit) {
    u32 pid;
    u32 *exists;

    pid = bpf_get_current_pid_tgid() >> 32;
    exists = processes.lookup(&pid);
    if (!exists) {
        return 0;
    }

    processes.delete(&pid);
    bpf_trace_printk("Process %d exited\\n", pid);
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

    // Track memory allocations
    if (event.syscall_id == 9) {  // mmap
        u64 size = event.arg1;
        u64 *current = memory_allocs.lookup(&pid);
        u64 new_size = size;
        if (current)
            new_size += *current;
        memory_allocs.update(&pid, &new_size);

        // Update peak if necessary
        u64 *peak = memory_peaks.lookup(&pid);
        if (!peak || new_size > *peak)
            memory_peaks.update(&pid, &new_size);
    }

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
            self.file_patterns = {
                'model_files': [],
                'weights': [],
                'configs': [],
                'temp_files': [],
                'libraries': []
            }
            print("BPF program loaded successfully")
        except Exception as e:
            print(f"Failed to initialize BPF: {str(e)}")
            raise

    def _analyze_file_patterns(self, events):
        for event in events:
            if not event.get('filename'):
                continue

            filename = event['filename'].lower()

            # Categorize files
            if any(ext in filename for ext in ['.bin', '.pt', '.pth', '.onnx', '.h5']):
                self.file_patterns['model_files'].append(filename)
            elif any(ext in filename for ext in ['.weight', '.weights', '.safetensors']):
                self.file_patterns['weights'].append(filename)
            elif any(ext in filename for ext in ['.json', '.yaml', '.config', '.cfg']):
                self.file_patterns['configs'].append(filename)
            elif any(ext in filename for ext in ['.so', '.dll', '.dylib']):
                self.file_patterns['libraries'].append(filename)
            elif '/tmp/' in filename or filename.startswith('/var/tmp/'):
                self.file_patterns['temp_files'].append(filename)

    def _process_event(self, cpu, data, size):
        try:
            event = self.bpf["syscall_events"].event(data)
            syscall_name = SYSCALLS.get(event.syscall_id, f"syscall_{event.syscall_id}")
            category = SYSCALL_TO_CATEGORY.get(event.syscall_id, "unknown")

            event_dict = {
                "timestamp": event.timestamp,
                "pid": event.pid,
                "tid": event.tid,
                "comm": event.comm.decode('utf-8', errors='replace'),
                "syscall_id": event.syscall_id,
                "syscall_name": syscall_name,
                "syscall_category": category,
                "args": [event.arg0, event.arg1, event.arg2],
                "return_value": event.ret,
                "filename": event.filename.decode('utf-8', errors='replace') if hasattr(event, 'filename') else None
            }
            self.events[event.pid].append(event_dict)

            print(f"PID {event.pid} [{category}]: {syscall_name}({event.arg0}, {event.arg1}, {event.arg2}) = {event.ret}")
            if hasattr(event, 'filename') and event.filename:
                print(f"  filename: {event.filename.decode('utf-8', errors='replace')}")

        except Exception as e:
            print(f"Error processing event: {str(e)}")

    def _get_process_memory(self, pid):
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            return {
                'timestamp': time.time(),  # Add timestamp
                'memory': {
                    'rss': memory_info.rss / 1024,
                    'vms': memory_info.vms / 1024,
                    'shared': getattr(memory_info, 'shared', 0) / 1024
                }
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
        category_counts = defaultdict(int)

        for event in events:
            syscall_id = event["syscall_id"]
            category = event["syscall_category"]

            syscall_counts[syscall_id] += 1
            category_counts[category] += 1

        return {
            "by_syscall": dict(syscall_counts),
            "by_category": dict(category_counts)
        }

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

class ModelBehaviorAnalyzer:
    def __init__(self, trace_data):
        self.trace_data = trace_data
        self.phases = {
            'initialization': [],
            'loading': [],
            'inference': [],
            'cleanup': []
        }

    def analyze(self):
        for pid, process_data in self.trace_data['processes'].items():
            events = process_data['events']
            self._identify_phases(events)

        return {
            'phases': self.phases,
            'security_profile': self._analyze_security(),
            'resource_usage': self._analyze_resources(),
            'file_access_patterns': self._analyze_file_access()
        }

    def _identify_phases(self, events):
        if not events:
            return

        current_phase = 'initialization'
        phase_start = events[0]['timestamp']

        for event in events:
            if self._is_model_loading(event):
                if current_phase != 'loading':
                    self._mark_phase_transition(current_phase, 'loading', phase_start, event['timestamp'])
                    current_phase = 'loading'
                    phase_start = event['timestamp']
            elif self._is_inference(event):
                if current_phase != 'inference':
                    self._mark_phase_transition(current_phase, 'inference', phase_start, event['timestamp'])
                    current_phase = 'inference'
                    phase_start = event['timestamp']
            # cleanup phase detection
            elif self._is_cleanup(event):
                if current_phase != 'cleanup':
                    self._mark_phase_transition(current_phase, 'cleanup', phase_start, event['timestamp'])
                    current_phase = 'cleanup'
                    phase_start = event['timestamp']

    def _is_cleanup(self, event):
        return (event['syscall_category'] == 'file_ops' and
                event['syscall_name'] in ['close', 'munmap'] and
                event['args'][0] > 0)

    def _mark_phase_transition(self, from_phase, to_phase, start_time, end_time):
        self.phases[from_phase].append({
            'start': start_time,
            'end': end_time,
            'duration': end_time - start_time
        })

    def _is_model_loading(self, event):
        return (event['syscall_category'] == 'file_ops' and
                event.get('filename') and
                any(ext in event['filename'].lower()
                    for ext in ['.bin', '.pt', '.pth', '.onnx', '.h5']))

    def _is_inference(self, event):
        return (event['syscall_category'] == 'memory_ops' and
                event['syscall_name'] == 'mmap' and
                event['args'][1] > 1024 * 1024)  # Large memory allocations

    def _analyze_security(self):
        security_indicators = {
            'suspicious_files': [],
            'network_connections': [],
            'unusual_syscalls': [],
            'permission_escalation': []
        }

        for pid, process_data in self.trace_data['processes'].items():
            for event in process_data['events']:
                # Check for suspicious file access
                if event.get('filename'):
                    if any(path in event['filename']
                          for path in ['/etc/', '/var/log/', '/root/']):
                        security_indicators['suspicious_files'].append(event)

                # Check for unusual syscalls
                if event['syscall_category'] == 'unknown':
                    security_indicators['unusual_syscalls'].append(event)

        return security_indicators

    def _analyze_resources(self):
        return {
            'memory_profile': self._analyze_memory_usage(),
            'file_usage': self._analyze_file_usage()
        }

    def _analyze_memory_usage(self):
        memory_profile = {
            'peak_usage': 0,
            'allocation_patterns': [],
            'potential_leaks': []
        }

        for pid, process_data in self.trace_data['processes'].items():
            peak_rss = process_data['peak_memory']['rss']
            memory_profile['peak_usage'] = max(memory_profile['peak_usage'], peak_rss)

            # Track memory allocation patterns
            allocs = defaultdict(int)
            for event in process_data['events']:
                if event['syscall_name'] == 'mmap':
                    allocs['allocated'] += event['args'][1]
                elif event['syscall_name'] == 'munmap':
                    allocs['freed'] += event['args'][1]

            # Check for potential leaks
            if allocs['allocated'] - allocs['freed'] > 1024 * 1024:  # more than 1MB difference
                memory_profile['potential_leaks'].append({
                    'pid': pid,
                    'allocated': allocs['allocated'],
                    'freed': allocs['freed'],
                    'difference': allocs['allocated'] - allocs['freed']
                })

        return memory_profile

    def _analyze_file_usage(self):
        return {
            'total_files': sum(len(p['file_operations'])
                             for p in self.trace_data['processes'].values()),
            'access_patterns': self._get_file_access_patterns()
        }

    def _get_file_access_patterns(self):
        patterns = defaultdict(int)
        for pid, process_data in self.trace_data['processes'].items():
            for op in process_data['file_operations'].values():
                for access in op:
                    ext = os.path.splitext(access['filename'])[1]
                    if ext:
                        patterns[ext] += 1
        return dict(patterns)

def main():
    if len(sys.argv) != 2:
        print("Usage: %s <python_script>" % sys.argv[0])
        sys.exit(1)

    try:
        print("Initializing eBPF tracer...")
        tracer = PythonTracer()

        print(f"Starting trace of {sys.argv[1]}...")
        trace_data = tracer.run_trace(sys.argv[1])

        # Add behavior analysis
        analyzer = ModelBehaviorAnalyzer(trace_data)
        behavior_profile = analyzer.analyze()
        trace_data['behavior_profile'] = behavior_profile

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
            print(f"  Syscall categories:")
            for category, count in data['syscall_summary']['by_category'].items():
                print(f"    - {category}: {count}")
            print(f"  File operations: {len(data['file_operations'])}")

        print("\nBehavior Analysis:")
        print("----------------")
        print("Execution Phases:")
        for phase, events in behavior_profile['phases'].items():
            if events:
                print(f"  {phase.title()}:")
                print(f"    Duration: {events[-1]['end'] - events[0]['start']:.2f}ns")
                print(f"    Events: {len(events)}")

        if behavior_profile['security_profile']['suspicious_files']:
            print("\nSecurity Alerts:")
            for file in behavior_profile['security_profile']['suspicious_files']:
                print(f"  Suspicious file access: {file['filename']}")

        print("\nFile Access Patterns:")
        print("-------------------")
        for category, files in tracer.file_patterns.items():
            if files:
                print(f"  {category.replace('_', ' ').title()}: {len(files)} files")

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()