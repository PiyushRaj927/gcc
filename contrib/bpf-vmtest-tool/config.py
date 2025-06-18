import platform
from pathlib import Path
import os

KERNEL_TARBALL_PREFIX_URL = "https://cdn.kernel.org/pub/linux/kernel/"
BASE_DIR = Path.home() / ".bpf-vmtest-tool"
ARCH = platform.machine()
KCONFIG_REL_PATHS = [
    "tools/testing/selftests/bpf/config",
    "tools/testing/selftests/bpf/config.vm",
    f"tools/testing/selftests/bpf/config.{ARCH}",
]
CC = os.getenv("CC", "gcc")
CFLAGS = os.getenv("CFLAGS", "-g -Wall")
LDFLAGS = os.getenv("LDFLAGS", "-lelf -lz -lbpf")
BPF_CC = os.getenv("BPF_CC", "bpf-unknown-none-gcc")
BPF_CFLAGS = os.getenv("BPF_CFLAGS", "-O2")
BPF_INCLUDES = os.getenv("BPF_INCLUDES", "-I/usr/local/include -I/usr/include")
