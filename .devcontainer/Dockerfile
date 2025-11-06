FROM ubuntu:24.04

# Install dependencies
RUN DEBIAN_FRONTEND=noninteractive apt update && \
    apt install -y --no-install-recommends software-properties-common && \
    add-apt-repository ppa:tkchia/build-ia16 && \
    apt update && \
    apt install -y --no-install-recommends \
    gcc-ia16-elf \
    libi86-ia16-elf \
    make \
    binutils \
    mtools \
    qemu-system-x86 \
    qemu-utils \
    git \
    gdb \
    nasm \
    python3 \
    python3-pip \
    xxd \
    file \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages for emulator
RUN pip3 install --no-cache-dir --break-system-packages unicorn capstone
