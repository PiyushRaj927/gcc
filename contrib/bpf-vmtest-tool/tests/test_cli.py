import sys
from unittest import mock
import pytest
from bpf import BPFProgram
import kernel
import main
import logging

logger = logging.getLogger(__name__)


@pytest.fixture
def openat_bpf_source(tmp_path):
    openat_bpf = tmp_path / "openat_bpf.c"
    openat_bpf.write_text(r"""
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>
    #include <bpf/bpf_core_read.h>

    char LICENSE[] SEC("license") = "GPL";

    int example_pid = 0;

    SEC("tracepoint/syscalls/sys_enter_openat")
    int handle_openat(struct trace_event_raw_sys_enter *ctx)
    {
        int pid = bpf_get_current_pid_tgid() >> 32;
        char filename[256]; // filename buffer
        bpf_probe_read_user(&filename, sizeof(filename), (void *)ctx->args[1]);
        bpf_printk("sys_enter_openat() called from PID %d for file: %s\n", pid,
            filename);

        return 0;
    }

    """)
    return openat_bpf


@pytest.fixture
def openat_bpf_obj(openat_bpf_source):
    bpf_program = BPFProgram(source_path=openat_bpf_source)
    bpf_program._compile_bpf()
    return bpf_program.bpf_obj


@pytest.fixture
def invalid_memory_access_bpf_source(tmp_path):
    invalid_memory_access_bpf = tmp_path / "invalid_memory_access_bpf.c"
    invalid_memory_access_bpf.write_text(r"""
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>

    char LICENSE[] SEC("license") = "GPL";

    SEC("tracepoint/syscalls/sys_enter_openat")
    int bpf_prog(struct trace_event_raw_sys_enter *ctx) {
        int arr[4] = {1, 2, 3, 4};

        // Invalid memory access: out-of-bounds
        int val = arr[5];  // This causes the verifier to fail

        return val;
    }
    """)
    return invalid_memory_access_bpf


@pytest.fixture
def invalid_memory_access_bpf_obj(invalid_memory_access_bpf_source):
    bpf_program = BPFProgram(source_path=invalid_memory_access_bpf_source)
    bpf_program._compile_bpf()
    return bpf_program.bpf_obj


def run_main_with_args_and_capture_output(args, capsys):
    with mock.patch.object(sys, "argv", args):
        try:
            main.main()
        except SystemExit as e:
            result = capsys.readouterr()
            output = result.out.rstrip()
            error = result.err.rstrip()
            logger.debug("STDOUT:\n%s", output)
            logger.debug("STDERR:\n%s", error)
            return e.code, output, error


kernel_image_path = kernel.KernelManager().get_kernel_image(version="6.15")
kernel_cli_flags = [["--kernel", "6.15"], ["--kernel-image", f"{kernel_image_path}"]]


@pytest.mark.parametrize("kernel_args", kernel_cli_flags)
class TestCLI:
    def test_main_with_valid_bpf(self, kernel_args, openat_bpf_source, capsys):
        args = [
            "main.py",
            *kernel_args,
            "--rootfs",
            "/",
            "--bpf-src",
            str(openat_bpf_source),
        ]
        code, output, _ = run_main_with_args_and_capture_output(args, capsys)
        assert code == 0
        assert "BPF programs succesfully loaded" == output

    def test_main_with_valid_bpf_obj(self, kernel_args, openat_bpf_obj, capsys):
        args = [
            "main.py",
            *kernel_args,
            "--rootfs",
            "/",
            "--bpf-obj",
            str(openat_bpf_obj),
        ]
        code, output, _ = run_main_with_args_and_capture_output(args, capsys)
        assert code == 0
        assert "BPF programs succesfully loaded" == output

    def test_main_with_invalid_bpf(
        self, kernel_args, invalid_memory_access_bpf_source, capsys
    ):
        args = [
            "main.py",
            *kernel_args,
            "--rootfs",
            "/",
            "--bpf-src",
            str(invalid_memory_access_bpf_source),
        ]
        code, output, _ = run_main_with_args_and_capture_output(args, capsys)
        output_lines = output.splitlines()
        assert code == 1
        assert "BPF program failed to load" == output_lines[0]
        assert "Verifier logs:" == output_lines[1]

    def test_main_with_invalid_bpf_obj(
        self, kernel_args, invalid_memory_access_bpf_obj, capsys
    ):
        args = [
            "main.py",
            *kernel_args,
            "--rootfs",
            "/",
            "--bpf-obj",
            str(invalid_memory_access_bpf_obj),
        ]
        code, output, _ = run_main_with_args_and_capture_output(args, capsys)
        output_lines = output.splitlines()
        assert code == 1
        assert "BPF program failed to load" == output_lines[0]
        assert "Verifier logs:" == output_lines[1]

    def test_main_with_valid_command(self, kernel_args, capsys):
        args = ["main.py", *kernel_args, "--rootfs", "/", "-c", "uname -r"]
        code, output, error = run_main_with_args_and_capture_output(args, capsys)
        assert code == 0
        assert "6.15.0" == output

    def test_main_with_invalid_command(self, kernel_args, capsys):
        args = ["main.py", *kernel_args, "--rootfs", "/", "-c", "NotImplemented"]
        code, output, error = run_main_with_args_and_capture_output(args, capsys)
        assert code != 0
        assert f"Command failed with exit code: {code}" in output
