#!/usr/bin/env python3
from bcc import BPF
import json
import sys
import time
import os
import signal
import psutil
import logging
import subprocess
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

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
        """Initialize the Python tracer."""
        try:
            self.bpf = BPF(text=bpf_text, debug=0)
            self.events = defaultdict(list)
            self.memory_stats = defaultdict(list)
            self.start_time = time.time()
            # Initialize tracking structures
            self.file_operations = defaultdict(list)
            self.file_patterns = {
                'model_files': [],
                'configs': [],
                'temp_files': [],
                'libraries': [],
                'weights': []
            }
            self.phases = defaultdict(list)
            logger.info("BPF program loaded successfully")
        except Exception as e:
            logger.error(f"Failed to initialize BPF: {str(e)}")
            raise

    def signal_handler(self, signum, frame):
        """Handle interrupt signals."""
        logger.info("\nReceived interrupt signal, cleaning up...")
        if hasattr(self, 'process') and self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

        # Save any collected data
        try:
            if hasattr(self, 'trace_data') and self.trace_data:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                output_dir = os.path.join(os.getcwd(), 'traces')
                os.makedirs(output_dir, exist_ok=True)
                output_file = os.path.join(output_dir, f"trace_results_interrupted_{timestamp}.json")
                with open(output_file, "w") as f:
                    json.dump(self.trace_data, indent=2, fp=f)
                logger.info(f"Saved partial trace data to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save trace data during cleanup: {e}")

        self._cleanup()
        sys.exit(0)

    def _process_event(self, cpu, data, size):
        """Process each syscall event from the ring buffer."""
        try:
            event = self.bpf["syscall_events"].event(data)
            syscall_name = SYSCALLS.get(event.syscall_id, f"syscall_{event.syscall_id}")
            category = SYSCALL_TO_CATEGORY.get(event.syscall_id, "unknown")

            # Decode filename if present
            filename = event.filename.decode('utf-8', errors='replace') if event.filename else None

            # Decode command
            comm = event.comm.decode('utf-8', errors='replace')

            event_dict = {
                "timestamp": event.timestamp,
                "pid": event.pid,
                "tid": event.tid,
                "comm": comm,
                "syscall_id": event.syscall_id,
                "syscall_name": syscall_name,
                "syscall_category": category,
                "args": [event.arg0, event.arg1, event.arg2],
                "return_value": event.ret,
                "filename": filename
            }

            # Store the event
            self.events[event.pid].append(event_dict)

            # Track file operations
            if filename and category == 'file_ops':
                logger.debug(f"Processing file operation: {filename} for PID {event.pid}")
                self.file_operations[event.pid].append({
                    'timestamp': event.timestamp,
                    'operation': syscall_name,
                    'filename': filename,
                    'result': event.ret
                })
                logger.debug(f"Current file_operations count for PID {event.pid}: {len(self.file_operations[event.pid])}")

                ## Initialize file_patterns if not exists
                #if not hasattr(self, 'file_patterns'):
                #    self.file_patterns = {
                #        'model_files': [],
                #        'configs': [],
                #        'temp_files': [],
                #        'libraries': [],
                #        'weights': []
                #    }

                # Categorize file access patterns - for real-time tracking of unique files
                if any(ext in filename.lower() for ext in ['.bin', '.pt', '.pth', '.onnx']):
                    self.file_patterns['model_files'].append(filename)
                elif any(ext in filename.lower() for ext in ['.json', '.yaml', '.config']):
                    self.file_patterns['configs'].append(filename)
                elif '/tmp/' in filename:
                    self.file_patterns['temp_files'].append(filename)
                elif '.so' in filename or '.py' in filename:
                    self.file_patterns['libraries'].append(filename)
                elif '.weight' in filename or '.bias' in filename:
                    self.file_patterns['weights'].append(filename)

            # Track execution phases
            if "PHASE" in comm:  # More lenient phase detection
                logger.debug(f"Processing comm string: {comm}")
                try:
                    phase_name = comm.split("===")[1].split("PHASE")[0].strip().lower() if "===" in comm else \
                                comm.split("PHASE")[0].strip().lower()
                    logger.debug(f"Detected potential phase in comm: {comm}")

                    self.phases[phase_name].append({
                        'start': event.timestamp,
                        'end': event.timestamp + 1000000,  # Add 1ms duration
                        'pid': event.pid,
                        'event': event_dict
                    })
                    logger.debug(f"Added phase: {phase_name}")
                except Exception as e:
                    logger.debug(f"Failed to parse phase from comm: {comm}, error: {e}")

            # Debug logging
            logger.debug(f"PID {event.pid} [{category}]: {syscall_name}({event.arg0}, {event.arg1}, {event.arg2}) = {event.ret}")
            if filename:
                logger.debug(f"  filename: {filename}")

        except Exception as e:
            logger.error(f"Error processing event: {str(e)}")

    def _get_process_memory(self, pid):
        """Safely get process memory information."""
        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            return {
                'rss': memory_info.rss / 1024 if memory_info.rss is not None else 0,  # Convert to KB
                'vms': memory_info.vms / 1024 if memory_info.vms is not None else 0,
                'shared': getattr(memory_info, 'shared', 0) / 1024
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
            logger.debug(f"Could not get memory info for PID {pid}: {str(e)}")
            return {
                'rss': 0,
                'vms': 0,
                'shared': 0
            }

    def run_trace(self, command, timeout=120):
        """Run the trace on a Python script."""
        try:
            # Split command if it's a string
            if isinstance(command, str):
                command = command.split()

            script_name = os.path.basename(command[1])
            logger.info(f"Starting trace of {script_name}... (timeout: {timeout}s)")
            logger.info(f"Starting trace of script: {script_name}")

            # Initialize data structures
            # self.events = defaultdict(list)
            # self.memory_stats = defaultdict(list)
            # self.file_patterns = defaultdict(list)
            # self.phases = defaultdict(list)

            # Start tracing
            self.bpf["syscall_events"].open_ring_buffer(self._process_event)

            # Run the Python script
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.path.dirname(command[1])
            )

            logger.info(f"Started process with PID: {process.pid}")
            logger.info(f"Tracing process (will timeout after {timeout}s)...")

            # Store process for cleanup
            self.process = process

            # Monitor the process
            start_time = time.time()
            logger.info("Starting event polling loop...")

            while process.poll() is None:
                try:
                    # Poll for events
                    logger.debug("Polling for events...")
                    events = self.bpf.ring_buffer_poll()
                    logger.debug(f"Received {events} events")

                    # Check memory usage
                    try:
                        proc = psutil.Process(process.pid)
                        with proc.oneshot():
                            memory_info = proc.memory_full_info()
                            self.memory_stats[process.pid].append({
                                'timestamp': time.time(),
                                'memory': {
                                    'rss': memory_info.rss / 1024,
                                    'vms': memory_info.vms / 1024,
                                    'shared': memory_info.shared / 1024
                                }
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        logger.debug("Process no longer exists or access denied")
                        break

                    # Check timeout
                    elapsed = time.time() - start_time
                    if elapsed > timeout:
                        logger.warning(f"Trace timed out after {timeout} seconds")
                        process.terminate()
                        break

                    # Check process output
                    stdout_data = process.stdout.readline()
                    if stdout_data:
                        logger.debug(f"Process output: {stdout_data.strip()}")

                    time.sleep(0.1)  # Prevent CPU overload

                except KeyboardInterrupt:
                    logger.info("\nReceived interrupt signal")
                    break

            logger.info("Event polling loop completed")

            # Check process status
            exit_code = process.poll()
            logger.info(f"Process exited with code: {exit_code}")

            # Generate trace data
            trace_data = self._generate_trace_data(command[1])

            # Save results
            # timestamp = time.strftime("%Y%m%d_%H%M%S")
            # output_dir = os.path.join(os.path.dirname(command[1]), 'traces')
            # os.makedirs(output_dir, exist_ok=True)
            # output_file = os.path.join(output_dir, f"trace_results_{timestamp}.json")

            # with open(output_file, "w") as f:
            #     json.dump(trace_data, f, indent=2)

            # logger.info(f"\nTrace completed. Results saved to {output_file}")

            return trace_data

        except Exception as e:
            logger.error(f"Error during tracing: {str(e)}")
            raise
        finally:
            try:
                if hasattr(self, 'process') and self.process:
                    self.process.terminate()
            except Exception:
                pass
            self._cleanup()

    def _cleanup(self):
        """Cleanup resources."""
        try:
            self.bpf.cleanup()
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

    def _generate_trace_data(self, python_script):
        """Generate the final trace data structure."""
        logger.debug(f"Generating trace data for {python_script}")
        logger.debug(f"File operations tracked: {dict(self.file_operations)}")

        trace_data = {
            "metadata": {
                "script": python_script,
                "duration": time.time() - self.start_time,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "processes": {},
            "phases": dict(self.phases),  # Convert defaultdict to regular dict
            "file_patterns": {k: list(set(v)) for k, v in self.file_patterns.items()}  # Deduplicate files
        }

        # Process data for each PID
        for pid in set(pid for pid_list in [self.events.keys(), self.file_operations.keys()] for pid in pid_list):
            logger.debug(f"Processing PID {pid}")
            logger.debug(f"Events count: {len(self.events.get(pid, []))}")
            logger.debug(f"File operations count: {len(self.file_operations.get(pid, []))}")

            events = self.events.get(pid, [])
            file_ops = self.file_operations.get(pid, [])
            memory_data = self.memory_stats.get(int(pid), [])

            trace_data["processes"][str(pid)] = {
                "events": events,
                "event_count": len(events),
                "syscall_summary": self._summarize_syscalls(events),
                "file_operations": file_ops,
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
        """Summarize file operations from the collected events."""
        if not hasattr(self, 'file_operations'):
            return []

        # Get the pid from the first event
        pid = events[0]['pid'] if events else None
        if not pid:
            return []

        # Return the file operations for this pid
        return self.file_operations.get(pid, [])

class ModelBehaviorAnalyzer:
    def __init__(self, trace_data):
        """Initialize the behavior analyzer."""
        self.trace_data = trace_data
        # Initialize phases with empty lists
        self.phases = {
            'initialization': [],
            'loading': [],
            'inference': [],
            'cleanup': []
        }
        # Add file patterns tracking
        self.file_patterns = {
            'model_files': [],
            'weights': [],
            'configs': [],
            'temp_files': [],
            'libraries': []
        }

    def analyze(self):
        for pid, process_data in self.trace_data['processes'].items():
            events = process_data['events']
            self._identify_phases(events)

        return {
            'phases': self.phases,
            'security_profile': self._analyze_security(),
            'resource_usage': self._analyze_resources(),
            'file_access': self._analyze_file_access()  # Make sure it's called like this
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
            try:
                peak_rss = process_data.get('peak_memory', {}).get('rss', 0)
                if peak_rss:  # Only update if we have a valid peak_rss
                    memory_profile['peak_usage'] = max(memory_profile['peak_usage'], peak_rss)

                # Track memory allocation patterns
                allocs = defaultdict(int)
                for event in process_data.get('events', []):
                    if event.get('syscall_name') == 'mmap':
                        args = event.get('args', [0, 0, 0])
                        if len(args) > 1 and args[1]:
                            allocs['allocated'] += args[1]
                    elif event.get('syscall_name') == 'munmap':
                        args = event.get('args', [0, 0, 0])
                        if len(args) > 1 and args[1]:
                            allocs['freed'] += args[1]

                # Check for potential leaks
                if allocs['allocated'] - allocs['freed'] > 1024 * 1024:  # more than 1MB difference
                    memory_profile['potential_leaks'].append({
                        'pid': pid,
                        'allocated': allocs['allocated'],
                        'freed': allocs['freed'],
                        'difference': allocs['allocated'] - allocs['freed']
                    })
            except Exception as e:
                logger.debug(f"Error analyzing memory for PID {pid}: {str(e)}")
                continue

        return memory_profile

    def _analyze_file_usage(self):
        """Analyze file usage patterns."""
        return {
            'total_files': sum(len(p['file_operations'])
                              for p in self.trace_data['processes'].values()),
            'access_patterns': self._get_file_access_patterns()
        }

    def _get_file_access_patterns(self):
        """Analyze file access patterns from the trace data."""
        patterns = defaultdict(int)
        for pid, process_data in self.trace_data['processes'].items():
            # file_operations is now a list, not a dict
            for op in process_data['file_operations']:  # Remove .values()
                ext = os.path.splitext(op['filename'])[1]
                if ext:
                    patterns[ext] += 1
        return dict(patterns)

    def _analyze_file_access(self):
        """Analyze file access patterns and behaviors."""
        file_access = {
            'patterns': self._get_file_access_patterns(),
            'summary': {
                'reads': 0,
                'writes': 0,
                'model_files': 0,
                'config_files': 0,
                'temp_files': 0
            }
        }

        for pid, process_data in self.trace_data['processes'].items():
            for event in process_data.get('events', []):
                if event.get('filename'):
                    filename = event['filename'].lower()

                    # Count reads and writes
                    if event['syscall_name'] == 'read':
                        file_access['summary']['reads'] += 1
                    elif event['syscall_name'] == 'write':
                        file_access['summary']['writes'] += 1

                    # Categorize file types - for operation counts and summary stats
                    if any(ext in filename for ext in ['.bin', '.pt', '.pth', '.onnx', '.h5']):
                        file_access['summary']['model_files'] += 1
                    elif any(ext in filename for ext in ['.json', '.yaml', '.config']):
                        file_access['summary']['config_files'] += 1
                    elif '/tmp/' in filename or filename.startswith('/var/tmp/'):
                        file_access['summary']['temp_files'] += 1

        return file_access

def main():
    if len(sys.argv) < 2:
        logger.error("Usage: %s <python_script>" % sys.argv[0])
        sys.exit(1)

    try:
        script_path = os.path.abspath(sys.argv[1])
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script not found: {script_path}")

        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.path.dirname(script_path), 'traces')
        os.makedirs(output_dir, exist_ok=True)

        # Set up the command with any additional arguments
        command = [sys.executable, script_path] + sys.argv[2:]
        logger.info(f"Starting trace of {script_path}...")

        # Create and run tracer
        tracer = PythonTracer()
        trace_data = tracer.run_trace(command)  # Using default timeout of 120s

        # Add behavior analysis
        analyzer = ModelBehaviorAnalyzer(trace_data)
        behavior_profile = analyzer.analyze()
        trace_data['behavior_profile'] = behavior_profile

        # Save results
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"trace_results_{timestamp}.json")
        with open(output_file, "w") as f:
            json.dump(trace_data, indent=2, fp=f)

        logger.info(f"\nTrace completed. Results saved to {output_file}")
        logger.info("\nSummary:")
        logger.info("--------")

        # Print summary information
        try:
            profile_files = [f for f in os.listdir(output_dir)
                           if f.startswith('profile_') and f.endswith('.json')]
            if profile_files:
                latest_profile = max(profile_files,
                                   key=lambda x: os.path.getctime(os.path.join(output_dir, x)))
                with open(os.path.join(output_dir, latest_profile)) as f:
                    profile_data = json.load(f)
                    model_path = profile_data.get('metadata', {}).get('model_path')
                    if model_path:
                        print(f"Model scanned: {model_path}")
            else:
                print("Model path not found in profile data")
        except Exception as e:
            logger.debug(f"Could not read model path from profile: {e}")
            print("Model path not found in profile data")

        # Print process information
        for pid, data in trace_data["processes"].items():
            print(f"PID {pid}:")
            print(f"  Total syscalls: {data['event_count']}")
            print(f"  Peak RSS: {data['peak_memory']['rss']:.2f} KB")
            print(f"  Syscall categories:")
            for category, count in data['syscall_summary']['by_category'].items():
                print(f"    - {category}: {count}")
            print(f"  File operations: {len(data['file_operations'])}")

        # Print behavior analysis
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