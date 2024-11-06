FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3.10 \
    python3.10-dev \
    python3-pip \
    linux-headers-generic \
    build-essential \
    git \
    seccomp \
    apparmor \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc \
    libbpfcc-dev \
    llvm-14 \
    llvm-14-dev \
    libllvm14 \
    clang-14 \
    libclang-14-dev \
    python3-clang-14 \
    libedit-dev \
    bison \
    flex \
    liblzma-dev \
    libdebuginfod-dev \
    zip \
    unzip \
    iperf \
    iperf3 \
    arping \
    netperf \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash appuser
RUN mkdir /app && chown appuser:appuser /app

# Switch to root temporarily to install system-wide packages
USER root

# Create symlinks for BCC Python bindings
RUN ln -sf /usr/lib/python3/dist-packages/bcc /usr/local/lib/python3.10/dist-packages/ && \
    ln -sf /usr/lib/python3/dist-packages/_bcc.so /usr/local/lib/python3.10/dist-packages/

# Switch back to non-root user
USER appuser
WORKDIR /app

# Copy files with correct permissions
COPY --chown=appuser:appuser ebpf_tracer.py /app/
COPY --chown=appuser:appuser loader.py /app/
COPY --chown=appuser:appuser requirements.txt /app/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Make scripts executable
RUN chmod +x /app/ebpf_tracer.py /app/loader.py

# Set the entrypoint
ENTRYPOINT ["/app/ebpf_tracer.py"]