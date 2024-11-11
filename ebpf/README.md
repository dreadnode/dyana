# eBPF Runtime Profiler for ML Models

This tool uses eBPF to trace and profile the runtime behavior of ML model loading and inference. It captures detailed system-level information including syscalls, memory usage, and process behavior.

- [eBPF Runtime Profiler for ML Models](#ebpf-runtime-profiler-for-ml-models)
  - [Output](#output)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
  - [Verifying Setup](#verifying-setup)
  - [Troubleshooting](#troubleshooting)
    - [Finding the Right Kernel Version](#finding-the-right-kernel-version)
    - [Run just the `loader.py`:](#run-just-the-loaderpy)
  - [Inspiration \& Credits](#inspiration--credits)
  - [Notes](#notes)
    - [Other useful debugging:](#other-useful-debugging)

## Output

The tracer generates JSON data containing:
- Syscall traces from the Python process
- Memory usage over time
- Process information
- Execution duration
- File operations

- `-PythonTracer` class with all essential methods:
    - `__init__`
    - `_analyze_file_patterns`
    - `_process_event`
    - `_get_process_memory`
    - `run_trace` (needs to be added)
- `ModelBehaviorAnalyzer` class with all analysis methods:
    - `__init__`
    - `analyze`
    - `_identify_phases`
    - `_is_cleanup`
    - `_mark_phase_transition`
    - `_is_model_loading`
    - `_is_inference`
    - `_analyze_security`
    - `_analyze_resources`
    - `_analyze_memory_usage`
    - `_analyze_file_usage`
    - `_get_file_access_patterns`

## Prerequisites

- Docker Desktop for Mac with virtualization support
- The correct kernel headers (currently using 5.10.25)

## Quick Start

1. Build and run in one command:
```bash
docker build -t ebpf-tracer . && \
docker run -it --rm \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_PTRACE \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v $(pwd):/root/ebpf \
    --pid=host \
    ebpf-tracer \
    sh -c "cd /root/ebpf && python3 ebpf_tracer.py ebpf_bert_tiny_loader.py --debug" # ie loading bert_tiny from tokenizers
```

Or, if you prefer step by step:

1. Build the container:
```bash
docker build -t ebpf-tracer .
```

2. Run the container in interactive mode:
```bash
# Important: Do NOT mount /lib/modules as we need to use the container's kernel headers
docker run -it --rm \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_PTRACE \
    -v /sys/kernel/debug:/sys/kernel/debug \
    --pid=host \
    ebpf-tracer
```

Inside the container, run the tracer:

        python3 ebpf_tracer.py "ebpf_bert_tiny_loader.py --debug"  # Uses default test model
        python3 ebpf_tracer.py "ebpf_loader_dynamic.py --debug --path /root/model" # specify and dynamically load a model

3. Run the tracer with a mount current directory to `/root/ebpf` in container if for example when making local development changes to [the tracer](./ebpf_tracer.py) and using a default small model

```shell
docker run -it --rm \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_PTRACE \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v $(pwd):/root/ebpf \
    --pid=host \
    ebpf-tracer \
    sh -c "cd /root/ebpf && python3 ebpf_tracer.py ebpf_bert_tiny_loader.py --debug && ls -la traces/"
```

4. Run the tracer with a mount current directory to `/root/ebpf` in container if making local development changes to [the tracer](./ebpf_tracer.py) whilst specifying the model using `-v /path/to/your/model:/root/model \` and the `ebpf_loader_dynamic.py` dynamic loader

```shell
docker run -it --rm \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_PTRACE \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /path/to/your/model:/root/model \
    -v $(pwd):/root/ebpf \
    --pid=host \
    ebpf-tracer \
    sh -c "cd /root/ebpf && python3 ebpf_tracer.py ebpf_loader_dynamic.py --debug && ls -la traces/"
```


## Verifying Setup

To verify the kernel headers are correctly linked:
```bash
ls -la /lib/modules/6.10.11-linuxkit/build
```

Should show:
```
lrwxrwxrwx 1 root root 39 ... /lib/modules/6.10.11-linuxkit/build -> /usr/src/linux-headers-5.10.25-linuxkit
```

## Troubleshooting

### Finding the Right Kernel Version

1. Check your current kernel version:
```bash
docker run --rm --privileged alpine uname -r
```

2. List available kernel versions:
```bash
curl -s "https://registry.hub.docker.com/v2/repositories/docker/for-desktop-kernel/tags/?page_size=100" | jq -r '.results[].name'
```

3. Update the Dockerfile's FROM line if needed:
```dockerfile
FROM docker/for-desktop-kernel:<your-version> AS ksrc
```

### Run just the `loader.py`:

```shell
➜  ebpf git:(ebpf/ebpf-tracer-enhancements-v2) docker run -it --rm \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_PTRACE \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v $(pwd):/root/ebpf \
    --pid=host \
    ebpf-tracer \
    sh -c "cd /root/ebpf && python3 loader.py"
Loading model prajjwal1/bert-tiny...
config.json: 100%|███████████████████████████████████████████████| 285/285 [00:00<00:00, 1.41MB/s]
vocab.txt: 100%|███████████████████████████████████████████████| 232k/232k [00:00<00:00, 11.1MB/s]
pytorch_model.bin: 100%|█████████████████████████████████████| 17.8M/17.8M [00:00<00:00, 70.8MB/s]
Running inference 1/5...
Running inference 2/5...
Running inference 3/5...
Running inference 4/5...
Running inference 5/5...
Model testing completed successfully!
```

## Inspiration & Credits

- [Pulsar by Exein](https://github.com/exein-io/pulsar)
- [eBPF Docker for Mac](https://github.com/singe/ebpf-docker-for-mac)
- Special thanks to @evilsocket

## Notes

- The container must run with `--privileged` and appropriate capabilities for eBPF access
- We intentionally avoid mounting `/lib/modules` to prevent host kernel headers from overriding container setup
- The tracer is designed to work with ARM64 architecture (Apple Silicon)

- On x86, syscall arguments are passed in specific registers (di, si, dx)
- On ARM64 (and other architectures), arguments are passed in a generic register array
- regs->regs[0] always refers to the first argument regardless of architecture
- This makes our code portable across different CPU architectures
- ie:

```python
     * Architecture-agnostic argument access
     * Works on any architecture including:
     * - ARM64 (Apple Silicon)
     * - x86_64
     * - aarch64
     */
    #ifdef __x86_64__
        bpf_probe_read(&event.arg0, sizeof(event.arg0), &regs->di);  // di register
        bpf_probe_read(&event.arg1, sizeof(event.arg1), &regs->si);  // si register
        bpf_probe_read(&event.arg2, sizeof(event.arg2), &regs->dx);  // dx register
    #else
        bpf_probe_read(&event.arg0, sizeof(event.arg0), &regs->regs[0]);  // First argument
        bpf_probe_read(&event.arg1, sizeof(event.arg1), &regs->regs[1]);  // Second argument
        bpf_probe_read(&event.arg2, sizeof(event.arg2), &regs->regs[2]);  // Third argument
    #endif
```

### Other useful debugging:

- Check Tracepoint Availability:

`root@63e1ebcdffc2:~# ls -al /sys/kernel/debug/tracing/events/sched/ `

<!-- ARCHIVE
```shell
# Create VM if you haven't already
multipass launch --name ebpf-dev --memory 4G --disk 10G

# Mount your project directory - since this is a private repo
# When you mount a local directory to Multipass, it creates a bidirectional sync. Changes made on either the host or guest will be reflected in both places immediately.
multipass mount ~/git/dyana ebpf-dev:/home/ubuntu/project

# Shell into VM
multipass shell ebpf-dev

# Inside VM, install dependencies
sudo apt-get update
sudo apt-get install -y docker.io
sudo apt-get install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

# Log out and back in for group changes to take effect
exit
multipass shell ebpf-dev

# Navigate to your mounted project directory
cd /project/ebpf-repo

..

ubuntu@ebpf-dev:~$ cd project/ebpf/
ubuntu@ebpf-dev:~/project/ebpf$ ls -al
total 44
drwxr-xr-x 1 ubuntu ubuntu  288 Nov  6 12:52 .
drwxr-xr-x 1 ubuntu ubuntu  320 Nov  6 09:08 ..
-rw-r--r-- 1 ubuntu ubuntu 1292 Nov  6 12:58 Dockerfile
-rw-r--r-- 1 ubuntu ubuntu 1201 Nov  6 12:58 README.md
-rw-r--r-- 1 ubuntu ubuntu  455 Nov  6 12:52 build.sh
-rwxr-xr-x 1 ubuntu ubuntu 9097 Nov  6 12:04 ebpf_tracer.py
-rw-r--r-- 1 ubuntu ubuntu  935 Nov  6 09:08 loader.py
-rw-r--r-- 1 ubuntu ubuntu  111 Nov  6 10:11 requirements.txt
-rw-r--r-- 1 ubuntu ubuntu  520 Nov  6 08:57 test_model.py

# Add your user to the docker group to run docker without sudo
sudo usermod -aG docker ubuntu

# Build the Docker image
docker build -t ebpf-model-tracer .

# Run the container with all necessary privileges and kernel headers
# When running the container, make sure to mount the debugfs and tracefs:
sudo docker run --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_PTRACE \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    -v /sys/kernel/debug:/sys/kernel/debug:rw \
    -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
    -v $(pwd):/app/mount \
    -v /usr/include:/usr/include:ro \
    --pid=host \
    ebpf-model-tracer mount/loader.py
```

If you want to test without Docker first:

```shell
# Install dependencies directly on the VM
sudo apt-get update
sudo apt-get install -y \
    python3 \
    python3-dev \
    python3-pip \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc \
    libbpfcc-dev \
    linux-headers-generic

# Install Python dependencies
pip3 install -r requirements.txt

# Run the tracer directly
sudo python3 ebpf_tracer.py loader.py
```
-->
