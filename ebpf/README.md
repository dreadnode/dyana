# EBPF approach to Runtime Profiling:

The tracer will output JSON data showing:
- All syscalls made by the Python process
- Memory usage over time
- Process information
- Execution duration
You can analyze the output to see:
- What system calls the model makes during loading
- Memory usage patterns
- Any suspicious behavior (unusual syscalls, file access patterns, etc.)
- Resource usage statistics

## To use this eBPF-based tracer: (Linux architecture)

- Create the files shown above (Dockerfile, requirements.txt, and bpf_tracer.py)
- Build and run the Docker container with privileged mode (required for eBPF):

```shell
# Get the kernel version
KERNEL_VERSION=$(uname -r)

# Build the image
docker build -t ebpf-model-tracer .

# Run the container with necessary privileges
docker run --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_PTRACE \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    -v /sys/kernel/debug:/sys/kernel/debug:rw \
    -v $(pwd):/app/mount \
    --pid=host \
    ebpf-model-tracer mount/loader.py
```

## To use this eBPF-based tracer: (Mac OS Architecture)

```shell
# Create VM if you haven't already
multipass launch --name ebpf-dev --memory 4G --disk 10G

# Mount your project directory - since this is a private repo
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
cd /home/ubuntu/project/ebpf-repo

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

## Build the Docker image
docker build -t ebpf-model-tracer .

## Run the container with all necessary privileges
docker run --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_PTRACE \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    -v /sys/kernel/debug:/sys/kernel/debug:rw \
    -v $(pwd):/app/mount \
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


## Inspiration

Inspiration:

- https://github.com/exein-io/pulsar
- https://github.com/exein-io/pulsar/tree/main/examples/pulsar-module-as-library