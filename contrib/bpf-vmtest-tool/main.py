import argparse
import logging
from pathlib import Path
import textwrap

import bpf
import kernel
import vm


def main():
    parser = argparse.ArgumentParser()
    kernel_group = parser.add_mutually_exclusive_group(required=True)
    kernel_group.add_argument(
        "-k",
        "--kernel",
        help="Kernel version to boot in the vm",
        metavar="VERSION",
        type=str,
    )
    kernel_group.add_argument(
        "--kernel-image",
        help="Kernel image to boot in the vm",
        metavar="PATH",
        type=str,
    )
    parser.add_argument(
        "-r", "--rootfs", help="rootfs to mount in the vm", default="/", metavar="PATH"
    )
    parser.add_argument(
        "-v",
        "--log-level",
        help="Log level",
        metavar="DEBUG|INFO|WARNING|ERROR",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="ERROR",
    )
    command_group = parser.add_mutually_exclusive_group(required=True)
    command_group.add_argument(
        "--bpf-src",
        help="Path to BPF C source file",
        metavar="PATH",
        type=str,
    )
    command_group.add_argument(
        "--bpf-obj",
        help="Path to bpf bytecode object",
        metavar="PATH",
        type=str,
    )
    command_group.add_argument(
        "-c", "--command", help="command to run in the vm", metavar="COMMAND"
    )
    command_group.add_argument(
        "-s", "--shell", help="open interactive shell in the vm", action="store_true"
    )

    args = parser.parse_args()

    logging.basicConfig(level=args.log_level)
    logger = logging.getLogger(__name__)
    kmanager = kernel.KernelManager()

    if args.kernel:
        kernel_image = kmanager.get_kernel_image(version=args.kernel)
    elif args.kernel_image:
        kernel_image = kmanager.get_kernel_image(kernel_image_path=args.kernel_image)

    if args.bpf_src:
        command = bpf.BPFProgram.from_source(Path(args.bpf_src))
    elif args.bpf_obj:
        command = bpf.BPFProgram.from_bpf_obj(Path(args.bpf_obj))
    elif args.command:
        command = args.command
    elif args.shell:
        # todo: somehow pass to hyperwiser that you need to attach stdin as well
        # command = "/bin/bash"
        raise NotImplementedError

    virtual_machine = vm.VirtualMachine(kernel_image, args.rootfs, str(command))
    try:
        result = virtual_machine.execute()
    except vm.BootFailedError as e:
        logger.error("VM boot failure: execution aborted. See logs for details.")
        print(e)
        exit(e.returncode)
    if args.bpf_src or args.bpf_obj:
        if result.returncode == 0:
            print("BPF programs succesfully loaded")
        else:
            if "Failed to load BPF skeleton" in result.stdout:
                print("BPF program failed to load")
                print("Verifier logs:")
                print(textwrap.indent(vm.bpf_verifier_logs(result.stdout), "\t"))
    elif args.command:
        print(result.stdout)
    exit(result.returncode)


if __name__ == "__main__":
    main()
