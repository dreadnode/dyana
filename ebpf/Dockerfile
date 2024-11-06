FROM ubuntu:22.04

# Install dependencies first
RUN apt-get update && apt-get install -y \
    python3.10 \
    python3.10-dev \
    python3-pip \
    linux-headers-generic \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc \
    libbpfcc-dev \
    kmod \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash appuser
RUN mkdir /app && chown appuser:appuser /app

# Switch to root temporarily to install system-wide packages
USER root

# Fix Python path for BCC
RUN mkdir -p /usr/local/lib/python3.10/dist-packages/ && \
    export PYTHONPATH=$(dirname $(find /usr/lib -name bcc)):$PYTHONPATH

# Create symlink for kernel headers
RUN mkdir -p /lib/modules/$(uname -r)/build && \
    ln -s /usr/src/linux-headers-$(uname -r) /lib/modules/$(uname -r)/build

# Remove any pip-installed bcc to avoid conflicts
RUN pip3 uninstall -y bcc || true

# Copy files with correct permissions
COPY --chown=appuser:appuser ebpf_tracer.py /app/
COPY --chown=appuser:appuser loader.py /app/
COPY --chown=appuser:appuser requirements.txt /app/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Make scripts executable
RUN chmod +x /app/ebpf_tracer.py /app/loader.py

# Switch to non-root user
USER appuser
WORKDIR /app

# Set the entrypoint with explicit Python path and kernel modules
ENTRYPOINT ["sh", "-c", "export PYTHONPATH=$(dirname $(find /usr/lib -name bcc)):$PYTHONPATH && python3 /app/ebpf_tracer.py $0 $@"]