# EBPF approach to

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

## To use this eBPF-based tracer:

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

## Inspiration

Inspiration:

- https://github.com/exein-io/pulsar
- https://github.com/exein-io/pulsar/tree/main/examples/pulsar-module-as-library