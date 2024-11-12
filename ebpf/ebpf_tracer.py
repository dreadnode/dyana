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
        0: "read",
        1: "write",
        87: "unlink",
        82: "rename",
        89: "readlink",
        88: "symlink",
        16: "lseek",
        19: "lstat",
        4: "stat",
        5: "fstat",
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
        event.syscall_id == 322 || // execve
        event.syscall_id == 437) { // openat2
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
            # Initialize data structures with default values
            self.events = defaultdict(list)
            self.memory_stats = defaultdict(list)
            self.file_operations = defaultdict(list)
            self.phases = defaultdict(list)
            self.file_patterns = {
                'model_files': [],
                'configs': [],
                'temp_files': [],
                'libraries': [],
                'weights': []
            }
            self.start_time = time.time()
            self.process = None
            self.trace_data = None
            self.bpf = None

            # Set up signal handlers
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)

            # Initialize BPF
            if not os.path.exists("/sys/kernel/debug"):
                logger.warning("debugfs not mounted. Attempting to mount...")
                os.system("mount -t debugfs debugfs /sys/kernel/debug")

            # Load BPF program
            try:
                self.bpf = BPF(text=bpf_text)
                logger.info("BPF program loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load BPF program: {e}")
                raise

            # Initialize syscall tracking
            self.syscall_stats = defaultdict(lambda: {
                'count': 0,
                'errors': 0,
                'total_time': 0
            })

            # Initialize phase tracking
            self.current_phase = None
            self.phase_start_time = None
            self.phase_events = defaultdict(list)

            # Initialize file tracking
            self.open_files = {}
            self.file_stats = defaultdict(lambda: {
                'opens': 0,
                'reads': 0,
                'writes': 0,
                'closes': 0,
                'total_bytes_read': 0,
                'total_bytes_written': 0
            })

            self.active_file_descriptors = {}  # Track open file descriptors

            # Initialize process tracking
            self.child_processes = set()
            self.process_stats = defaultdict(lambda: {
                'start_time': None,
                'end_time': None,
                'syscalls': 0,
                'file_ops': 0
            })

        except Exception as e:
            logger.error(f"Failed to initialize tracer: {e}")
            self._cleanup()
            raise

    def signal_handler(self, signum, frame):
        """Handle interrupt signals."""
        logger.info("\nReceived interrupt signal, cleaning up...")
        try:
            # Close ring buffer first
            if hasattr(self, 'bpf') and self.bpf:
                try:
                    self.bpf["syscall_events"].close_ring_buffer()
                except Exception as e:
                    logger.debug(f"Error closing ring buffer: {e}")

            # Save data
            if hasattr(self, 'events') and self.events:
                try:
                    trace_data = self._generate_trace_data("interrupted_trace")
                    timestamp = time.strftime("%Y%m%d_%H%M%S")
                    output_dir = os.path.join(os.getcwd(), 'traces')
                    os.makedirs(output_dir, exist_ok=True)
                    output_file = os.path.join(output_dir, f"trace_results_interrupted_{timestamp}.json")
                    with open(output_file, "w") as f:
                        json.dump(trace_data, indent=2, fp=f)
                    logger.info(f"Saved partial trace data to {output_file}")
                except Exception as e:
                    logger.error(f"Failed to save trace data during cleanup: {e}")

            if hasattr(self, 'bpf') and self.bpf:
                try:
                    self.bpf.cleanup()
                except Exception as e:
                    logger.debug(f"Error during BPF cleanup: {e}")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
        finally:
            os._exit(0)

    def _process_event(self, cpu, data, size):
        """Process a BPF event."""
        try:
            if not data:
                return

            event = self.bpf["syscall_events"].event(data)
            if not event:
                return

            # Get basic event info with safe defaults
            pid = getattr(event, 'pid', 0)
            timestamp = float(getattr(event, 'timestamp', 0))
            syscall_id = getattr(event, 'syscall_id', -1)
            syscall_name = SYSCALLS.get(syscall_id, "unknown")
            category = SYSCALL_TO_CATEGORY.get(syscall_id, "unknown")

            # Add debug logging
            logger.debug(f"Processing event: pid={pid}, syscall={syscall_id}")

            # Create event dictionary with safe values
            event_dict = {
                'timestamp': timestamp,
                'syscall_id': syscall_id,
                'syscall_name': syscall_name,
                'syscall_category': category,
                'ret': getattr(event, 'ret', 0),
                'comm': getattr(event, 'comm', b'').decode('utf-8', 'replace'),
                'arg0': getattr(event, 'arg0', 0),
                'arg1': getattr(event, 'arg1', 0),
                'arg2': getattr(event, 'arg2', 0)
            }

            # Safely get filename if it exists
            try:
                filename = getattr(event, 'filename', b'').decode('utf-8', 'replace')
                if filename:
                    event_dict['filename'] = filename
            except Exception:
                filename = None

            # Store the event
            if pid:
                self.events[pid].append(event_dict)

            # Enhanced file operation tracking
            if category == 'file_ops':
                pid_str = str(pid)

                # Track file descriptor operations
                if syscall_name in ('open', 'openat'):
                    if getattr(event, 'ret', -1) > 0:  # Successful open
                        fd = event.ret
                        self.active_file_descriptors[f"{pid_str}_{fd}"] = {
                            'filename': filename or '',
                            'opened_at': timestamp
                        }
                        self.file_stats[pid_str]['opens'] += 1

                elif syscall_name == 'close':
                    fd = getattr(event, 'arg0', -1)
                    fd_key = f"{pid_str}_{fd}"
                    if fd_key in self.active_file_descriptors:
                        self.file_stats[pid_str]['closes'] += 1
                        del self.active_file_descriptors[fd_key]

                elif syscall_name == 'read':
                    fd = getattr(event, 'arg0', -1)
                    bytes_read = getattr(event, 'ret', 0)
                    if bytes_read > 0:
                        self.file_stats[pid_str]['reads'] += 1
                        self.file_stats[pid_str]['total_bytes_read'] += bytes_read

                elif syscall_name == 'write':
                    fd = getattr(event, 'arg0', -1)
                    bytes_written = getattr(event, 'ret', 0)
                    if bytes_written > 0:
                        self.file_stats[pid_str]['writes'] += 1
                        self.file_stats[pid_str]['total_bytes_written'] += bytes_written

            # Track file operations (existing logic)
            if filename and category == 'file_ops':
                if pid:
                    self.file_operations[pid].append({
                        'timestamp': timestamp,
                        'operation': syscall_name,
                        'filename': filename,
                        'result': getattr(event, 'ret', 0)
                    })

                # Categorize file access patterns
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

            # Track execution phases safely
            comm = event_dict['comm']
            if "PHASE" in comm:
                try:
                    phase_name = comm.split("===")[1].split("PHASE")[0].strip().lower() if "===" in comm else \
                                comm.split("PHASE")[0].strip().lower()

                    if pid:
                        self.phases[phase_name].append({
                            'start': timestamp,
                            'end': timestamp + 1000000,  # Add 1ms duration
                            'pid': pid,
                            'event': event_dict
                        })
                except Exception as e:
                    logger.debug(f"Failed to parse phase from comm: {comm}, error: {e}")

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
        output_file = None
        try:
            # Store command for later use
            self.command = command if isinstance(command, list) else command.split()
            self.start_time = time.time()

            script_name = os.path.basename(self.command[1])
            logger.info(f"Starting trace of {script_name}... (timeout: {timeout}s)")
            logger.info(f"Starting trace of script: {script_name}")

            # Create output directory with explicit permissions
            self.output_dir = os.path.join(os.getcwd(), 'traces')
            os.makedirs(self.output_dir, mode=0o777, exist_ok=True)

            # Generate output filename early
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.output_dir, f"trace_results_{timestamp}.json")

            # Test file writing permission early
            try:
                with open(output_file, 'w') as f:
                    f.write("{}\n")
                logger.info(f"Successfully verified write access to {output_file}")
            except Exception as e:
                logger.error(f"Failed to write to output file: {e}")
                raise

            # Start tracing
            self.bpf["syscall_events"].open_ring_buffer(self._process_event)

            # Run the Python script
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,  # Line buffered
                universal_newlines=True,  # Text mode
                cwd=os.path.dirname(command[1])
            )

            logger.info(f"Started process with PID: {process.pid}")
            logger.info(f"Tracing process (will timeout after {timeout}s)...")

            # Store process for cleanup
            self.process = process

            # Monitor the process
            start_time = time.time()
            last_activity_time = start_time
            last_progress_time = start_time
            stdout_queue = []
            logger.info("Starting event polling loop...")

            event_count = 0
            while process.poll() is None:
                try:
                    # Poll for BPF events
                    events = self.bpf.ring_buffer_poll()

                    # Track activity and time
                    current_time = time.time()

                    # Add debug logging for events
                    if events:
                        event_count += events
                        logger.debug(f"Processed {events} events (total: {event_count})")
                        last_activity_time = current_time

                    elapsed_time = current_time - start_time
                    inactivity_time = current_time - last_activity_time

                    # Check for timeout or inactivity
                    if elapsed_time > timeout:
                        logger.warning(f"Trace timed out after {timeout} seconds")
                        break
                    elif inactivity_time > 10:  # 10 seconds of inactivity
                        logger.info("No events for 10 seconds, checking process status...")
                        if not process.stdout.readable():
                            logger.info("Process output stream closed, ending trace")
                            break
                        last_activity_time = current_time

                    # Track memory usage safely
                    try:
                        proc = psutil.Process(process.pid)
                        memory_info = proc.memory_info()
                        if memory_info:
                            memory_stats = {
                                'timestamp': current_time,
                                'memory': {
                                    'rss': getattr(memory_info, 'rss', 0) / 1024,
                                    'vms': getattr(memory_info, 'vms', 0) / 1024,
                                    'shared': getattr(memory_info, 'shared', 0) / 1024
                                }
                            }
                            self.memory_stats[process.pid].append(memory_stats)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
                        logger.debug(f"Could not get memory info: {e}")

                    # Print progress only if enough time has passed
                    if current_time - last_progress_time >= 5:
                        logger.info(f"Tracing in progress... ({int(elapsed_time)}s elapsed)")
                        last_progress_time = current_time

                    # Check process output with buffering
                    while True:
                        output = process.stdout.readline()
                        if not output:
                            break
                        stdout_queue.append(output.strip())
                        if len(stdout_queue) >= 10:
                            logger.info("Process output:\n" + "\n".join(stdout_queue))
                            stdout_queue = []

                    # Check stderr for any errors
                    stderr_output = process.stderr.readline()
                    if stderr_output:
                        logger.warning(f"Process stderr: {stderr_output.strip()}")

                    time.sleep(0.1)  # Prevent CPU overload

                except Exception as e:
                    logger.error(f"Error in polling loop: {str(e)}")
                    logger.debug("Error details:", exc_info=True)
                    continue

            # Flush any remaining output
            if stdout_queue:
                logger.info("Process output:\n" + "\n".join(stdout_queue))

            # Get process exit code
            exit_code = process.poll()
            logger.info(f"Process exited with code: {exit_code}")

            # Generate and save trace data with explicit error handling
            try:
                logger.info("Event polling loop completed")
                trace_data = self._generate_trace_data(command[1])

                # Add behavior analysis
                analyzer = ModelBehaviorAnalyzer(trace_data)
                behavior_profile = analyzer.analyze()
                trace_data['behavior_profile'] = behavior_profile

                with open(output_file, "w") as f:
                    json.dump(trace_data, indent=2, fp=f)
                logger.info(f"Trace data saved to {output_file}")

                # Verify the file was written
                if os.path.exists(output_file):
                    file_size = os.path.getsize(output_file)
                    logger.info(f"Verified file creation: {output_file} ({file_size} bytes)")
                else:
                    logger.error(f"File was not created: {output_file}")

                return trace_data

            except Exception as e:
                logger.error(f"Failed to save trace data: {e}")
                raise

        except Exception as e:
            logger.error(f"Error during tracing: {str(e)}")
            # Try to save partial data if we have an output file
            if output_file and hasattr(self, 'events'):
                try:
                    partial_data = self._generate_trace_data(command[1])
                    partial_file = output_file.replace('.json', '_partial.json')
                    with open(partial_file, "w") as f:
                        json.dump(partial_data, indent=2, fp=f)
                    logger.info(f"Saved partial trace data to {partial_file}")
                except Exception as save_error:
                    logger.error(f"Failed to save partial data: {save_error}")
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

    def _generate_trace_data(self, script_path):
        """Generate the final trace data structure."""
        logger.debug(f"Generating trace data for {script_path}")

        trace_data = {
            "metadata": {
                "script": script_path,
                "duration": time.time() - self.start_time,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "command": " ".join(self.command) if hasattr(self, 'command') else str(script_path)
            },
            "processes": {},
            "phases": dict(self.phases),
            "file_patterns": {k: list(set(v)) for k, v in self.file_patterns.items()}
        }

        # Process data for each PID
        for pid in set(pid for pid_list in [self.events.keys(), self.file_operations.keys()] for pid in pid_list):
            pid_str = str(pid)  # Convert pid to string for JSON compatibility
            events = self.events.get(pid, [])
            file_ops = self.file_operations.get(pid, [])
            memory_data = self.memory_stats.get(pid, [])

            trace_data["processes"][pid_str] = {
                "events": events,
                "event_count": len(events),
                "syscall_summary": {
                    "by_category": self._summarize_syscalls_by_category(events),
                    "by_name": self._summarize_syscalls_by_name(events)
                },
                "file_operations": file_ops,
                "memory_profile": memory_data,
                "peak_memory": {
                    'rss': max((m.get('memory', {}).get('rss', 0) for m in memory_data), default=0),
                    'vms': max((m.get('memory', {}).get('vms', 0) for m in memory_data), default=0),
                    'shared': max((m.get('memory', {}).get('shared', 0) for m in memory_data), default=0)
                }
            }

        return trace_data

    def _summarize_syscalls_by_category(self, events):
        """Summarize syscalls by category."""
        categories = defaultdict(int)
        for event in events:
            category = event.get('syscall_category', 'unknown')
            categories[category] += 1
        return dict(categories)

    def _summarize_syscalls_by_name(self, events):
        """Summarize syscalls by name."""
        syscalls = defaultdict(int)
        for event in events:
            name = event.get('syscall_name', 'unknown')
            syscalls[name] += 1
        return dict(syscalls)

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
        """Analyze the trace data."""
        try:
            for pid, process_data in self.trace_data.get('processes', {}).items():
                events = process_data.get('events', [])
                self._identify_phases(events)
        except Exception as e:
            logger.error(f"Error during analysis: {e}")

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
                event.get('arg0', 0) > 0)

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
                # Safely get peak memory values with defaults
                peak_memory = process_data.get('peak_memory', {})
                peak_rss = peak_memory.get('rss', 0) if peak_memory else 0

                # Update peak usage only if we have valid data
                if isinstance(peak_rss, (int, float)) and peak_rss > 0:
                    memory_profile['peak_usage'] = max(memory_profile['peak_usage'], peak_rss)

                # Track memory allocation patterns
                allocs = defaultdict(int)
                for event in process_data.get('events', []):
                    if event.get('syscall_name') == 'mmap':
                        args = event.get('args', [])
                        if len(args) > 1 and isinstance(args[1], (int, float)):
                            allocs['allocated'] += args[1]
                    elif event.get('syscall_name') == 'munmap':
                        args = event.get('args', [])
                        if len(args) > 1 and isinstance(args[1], (int, float)):
                            allocs['freed'] += args[1]

                # Check for potential leaks (only if we have valid allocation data)
                if allocs['allocated'] > 0 and allocs['freed'] > 0:
                    diff = allocs['allocated'] - allocs['freed']
                    if diff > 1024 * 1024:  # more than 1MB difference
                        memory_profile['potential_leaks'].append({
                            'pid': pid,
                            'allocated': allocs['allocated'],
                            'freed': allocs['freed'],
                            'difference': diff
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
    # Parse command line arguments
    if len(sys.argv) < 2:
        logger.error("Usage: %s <python_script> [args...]" % sys.argv[0])
        sys.exit(1)

    script_args = []
    target_script = sys.argv[1]

    # Handle --debug flag separately
    debug_mode = "--debug" in sys.argv
    if debug_mode:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
        # Remove --debug from args that will be passed to the target script
        sys.argv.remove("--debug")

    # Get remaining args for the target script
    if len(sys.argv) > 2:
        script_args = sys.argv[2:]

    try:
        # Parse command line arguments
        if "--" in sys.argv:
            separator_index = sys.argv.index("--")
            target_script = sys.argv[separator_index + 1]
            script_args = sys.argv[separator_index + 2:]
        else:
            target_script = sys.argv[1]
            script_args = sys.argv[2:]

        script_path = os.path.abspath(target_script)
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script not found: {script_path}")

        # Create output directory
        output_dir = os.path.join(os.getcwd(), 'traces')
        os.makedirs(output_dir, mode=0o777, exist_ok=True)

        # Generate output filename early
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"trace_results_{timestamp}.json")

        # Test file writing permission early
        try:
            with open(output_file, 'w') as f:
                f.write("{}\n")
            logger.info(f"Successfully verified write access to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write to output file: {e}")
            raise

        # Set up the command
        command = [sys.executable, script_path] + script_args
        logger.info(f"Starting trace of {' '.join(command)}...")

        # Create and run tracer
        tracer = PythonTracer()
        trace_data = tracer.run_trace(command)

        # Add behavior analysis
        analyzer = ModelBehaviorAnalyzer(trace_data)
        behavior_profile = analyzer.analyze()
        trace_data['behavior_profile'] = behavior_profile

        # Save results with timestamp
        with open(output_file, "w") as f:
            json.dump(trace_data, indent=2, fp=f)
            logger.info(f"Results saved to {output_file}")

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

        # Print detailed file statistics
        print("\nFile Operation Statistics:")
        print("-----------------------")
        for pid, data in trace_data["processes"].items():
            print(f"\nPID {pid} File Operations:")

            # Print detailed file statistics if available
            if "file_statistics" in data:
                stats = data["file_statistics"]
                print(f"  Detailed Statistics:")
                print(f"    Opens: {stats.get('opens', 0)}")
                print(f"    Reads: {stats.get('reads', 0)} (Total bytes: {stats.get('total_bytes_read', 0)})")
                print(f"    Writes: {stats.get('writes', 0)} (Total bytes: {stats.get('total_bytes_written', 0)})")
                print(f"    Closes: {stats.get('closes', 0)}")

            # Print operation counts (existing logic)
            if 'file_operations' in data:
                print(f"  Operation Counts:")
                op_counts = defaultdict(int)
                for op in data['file_operations']:
                    op_counts[op['operation']] += 1
                for op, count in op_counts.items():
                    print(f"    {op}: {count}")

            # Print active file descriptors if any
            if "active_file_descriptors" in data:
                active_fds = data["active_file_descriptors"]
                if active_fds:
                    print(f"  Active File Descriptors:")
                    for fd_key, fd_info in active_fds.items():
                        print(f"    {fd_key}: {fd_info['filename']}")

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()