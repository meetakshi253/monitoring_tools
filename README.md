# AOD Monitoring Tools

eBPF-based monitoring tools for tracing SMB/CIFS and NFS filesystem operations using libbpf CO-RE.

## Prerequisites

- Linux kernel with BTF support
- clang
- libbpf, libelf, zlib (dev packages)
- bpftool

On Ubuntu/Debian:
```bash
sudo apt install clang libbpf-dev libelf-dev zlib1g-dev linux-tools-common linux-tools-$(uname -r)
```

## Build

```bash
make            # build all tools
make smbslower  # build a single tool
make clean      # remove build artifacts
```

Binaries are placed in `src/bin/`, intermediate files (including the skel and object files) in `src/.output/`.

## Project Structure

```
src/
├── bpf/         # eBPF kernel-space programs (.bpf.c)
├── user/        # Userspace loaders (.c)
├── include/     # Shared headers (vmlinux.h, cifs_btf.h, diag structs)
└── shm_writer.c # Common shared memory ring buffer for event export
```

## Tools

- **smbslower** — Trace slow SMB/CIFS operations with configurable latency threshold and command filtering.

## Usage

```bash
sudo ./src/bin/smbslower -m 50          # trace ops slower than 50ms
sudo ./src/bin/smbslower -c 8,9         # trace only READ (0x08) and WRITE (0x09)
sudo ./src/bin/smbslower -x 13          # exclude ECHO commands
sudo ./src/bin/smbslower -d 30          # trace for 30 seconds
```
