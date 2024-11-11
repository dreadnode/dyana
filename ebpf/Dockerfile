FROM docker/for-desktop-kernel:5.10.25-6594e668feec68f102a58011bb42bd5dc07a7a9b AS ksrc

FROM ubuntu:latest

WORKDIR /
# Extract kernel headers from the kernel source
COPY --from=ksrc /kernel-dev.tar /
RUN tar xf kernel-dev.tar && rm kernel-dev.tar

# Install required packages
# Completely remove and recreate the directory structure and setup kernel headers for BPF compilation
# Note: We're linking the 5.10.25 headers to where BCC looks for the running kernel's headers
RUN apt-get update && apt-get install -y \
    kmod \
    python3-bpfcc \
    python3-pip \
    linux-headers-generic \
    build-essential

# Setup kernel headers
RUN rm -rf /lib/modules/6.10.11-linuxkit && \
    mkdir -p /lib/modules/6.10.11-linuxkit && \
    ln -sf /usr/src/linux-headers-5.10.25-linuxkit /lib/modules/6.10.11-linuxkit/build

# Additional kernel header setup
RUN mkdir -p /lib/modules/$(uname -r) && \
    ln -sf /usr/src/linux-headers-5.10.25-linuxkit /lib/modules/$(uname -r)/build && \
    ln -sf /usr/src/linux-headers-5.10.25-linuxkit /lib/modules/$(uname -r)/source

RUN mkdir -p /root/ebpf/traces && \
chmod 777 /root/ebpf/traces

# Install Python dependencies for the tracer and model loading
RUN pip3 install --break-system-packages psutil transformers torch

# Copy our files
COPY ebpf_tracer.py ebpf_bert_tiny_loader.py ebpf_loader_dynamic.py /root/

WORKDIR /root

# Make scripts executable
RUN chmod +x /root/ebpf_tracer.py /root/ebpf_bert_tiny_loader.py /root/ebpf_loader_dynamic.py
WORKDIR /root/ebpf

# Mount debugfs and start shell
# CMD ["sh", "-c", "mount -t debugfs debugfs /sys/kernel/debug && /bin/bash"]
CMD ["sh", "-c", "mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true && /bin/bash"]