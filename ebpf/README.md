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
# Clean up previous builds
docker system prune -a

# Build the container
docker build -t ebpf-model-tracer .

# Run the tracer with the test script
docker run --privileged -v $(pwd):/app ebpf-model-tracer test_model.py
```

If you still get errors, you might need to run with additional privileges:

```shell
docker run --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=SYS_RESOURCE \
    --cap-add=SYS_PTRACE \
    -v $(pwd):/app/mount \
    ebpf-model-tracer mount/loader.py
```

## Inspiration

Inspiration:

- https://github.com/exein-io/pulsar
- https://github.com/exein-io/pulsar/tree/main/examples/pulsar-module-as-library