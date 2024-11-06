FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-bpfcc \
    linux-headers-generic \
    build-essential \
    git \
    bpfcc-tools \
    libbpfcc \
    seccomp \
    apparmor \
    && rm -rf /var/lib/apt/lists/*

# Add capability to use eBPF
RUN setcap cap_sys_admin+eip /usr/bin/python3

# Create non-root user
RUN useradd -m -s /bin/bash appuser
USER appuser

WORKDIR /app

# Copy files with correct permissions
COPY --chown=appuser:appuser ebpf_tracer.py .
COPY --chown=appuser:appuser loader.py .
COPY --chown=appuser:appuser requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Set the entrypoint to the tracer script
ENTRYPOINT ["python3", "ebpf_tracer.py"]