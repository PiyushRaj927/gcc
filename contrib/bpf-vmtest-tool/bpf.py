import re
import subprocess
import logging
from pathlib import Path
import tempfile
from typing import Optional
import utils
from config import BPF_CC, BPF_CFLAGS, BPF_INCLUDES, LDFLAGS, CC, CFLAGS,ARCH

logger = logging.getLogger(__name__)

# https://git.sr.ht/~brianwitte/gcc-bpf-example/tree/master/item/Makefile


def generate_sanitized_name(path: Path):
    """generate sanitized c variable name"""
    name = re.sub(r"\W", "_", path.stem)
    if name and name[0].isdigit():
        name = "_" + name
    return name


class BPFProgram:
    tmp_base_dir = tempfile.TemporaryDirectory(prefix="vmtest")
    tmp_base_dir_path = Path(tmp_base_dir.name)

    def __init__(
        self,
        source_path: Optional[Path] = None,
        bpf_bytecode_path: Optional[Path] = None,
        use_temp_dir: bool = False,
    ):
        path = source_path or bpf_bytecode_path
        self.name = generate_sanitized_name(path)
        self.build_dir = self.__class__.tmp_base_dir_path / "ebpf_programs" / self.name

        if source_path:
            self.bpf_src = source_path
            self.bpf_obj = self.build_dir / f"{self.name}.bpf.o"
        else:
            self.bpf_obj = bpf_bytecode_path
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.bpf_skel = self.build_dir / f"{self.name}.skel.h"
        self.loader_src = self.build_dir / f"{self.name}-loader.c"
        self.output = self.build_dir / f"{self.name}.o"

    @classmethod
    def from_source(cls, source_path: Path):
        self = cls(source_path=source_path)
        self._compile_bpf()
        self._compile_from_bpf_bytecode()
        return self.output

    @classmethod
    def from_bpf_obj(cls, obj_path: Path):
        self = cls(bpf_bytecode_path=obj_path)
        self._compile_from_bpf_bytecode()
        return self.output

    def _compile_from_bpf_bytecode(self):
        self._generate_skeleton()
        self._compile_loader()

    def _compile_bpf(self):
        """Compile the eBPF program using gcc"""
        logger.info(f"Compiling eBPF source: {self.bpf_src}")
        cmd = [
            BPF_CC,
            f"-D__TARGET_ARCH_{ARCH}",
            "-gbtf",
            "-std=gnu17"]
        if BPF_CFLAGS != "":
            cmd.extend(BPF_CFLAGS.split(" "))
        cmd.extend(BPF_INCLUDES.split())
        cmd.extend([
            "-c",
            str(self.bpf_src),
            "-o",
            str(self.bpf_obj),
        ])
        logger.debug("".join(cmd))
        utils.run_command(cmd)
        logger.info(f"eBPF compiled: {self.bpf_obj}")

    def _generate_skeleton(self):
        """Generate the BPF skeleton header using bpftool"""
        logger.info(f"Generating skeleton: {self.bpf_skel}")
        cmd = ["bpftool", "gen", "skeleton", str(self.bpf_obj), "name", self.name]
        try:
            result = utils.run_command(cmd)
            with open(self.bpf_skel, "w") as f:
                f.write(result.stdout)
            logger.info("Skeleton generated.")
            logger.debug("bpftool output:\n%s", result.stdout)
            if result.stderr:
                logger.debug("bpftool output:\n%s", result.stderr)
        except subprocess.CalledProcessError as e:
            logger.error("Failed to generate skeleton.")
            logger.error("stdout:\n%s", e.stdout)
            logger.error("stderr:\n%s", e.stderr)
            raise

    def _compile_loader(self):
        """Compile the C loader program"""
        self.generate_loader()
        logger.info(f"Compiling loader: {self.loader_src}")
        cmd = [
            CC,
            *CFLAGS.split(" "),
            "-I",
            str(self.build_dir),
            str(self.loader_src),
            *LDFLAGS.split(" "),
            "-o",
            str(self.output),
        ]
        utils.run_command(cmd)
        logger.info("Compilation complete")

    def generate_loader(self):
        """
        Generate a loader C file for the given BPF skeleton.

        Args:
            bpf_name (str): Name of the BPF program (e.g. "prog").
            output_path (str): Path to write loader.c.
        """
        skeleton_header = f"{self.name}.skel.h"
        loader_code = f"""\
        #include <stdio.h>
        #include <stdlib.h>
        #include <signal.h>
        #include <unistd.h>
        #include <bpf/libbpf.h>
        #include "{skeleton_header}"

        #define LOG_BUF_SIZE 1024 * 1024

        static volatile sig_atomic_t stop;
        static char log_buf[LOG_BUF_SIZE];

        void handle_sigint(int sig) {{
            stop = 1;
        }}

        int main() {{
            struct {self.name} *skel;
            struct bpf_program *prog;
            int err;

            signal(SIGINT, handle_sigint);

            skel = {self.name}__open();  // STEP 1: open only
            if (!skel) {{
                fprintf(stderr, "Failed to open BPF skeleton\\n");
                return 1;
            }}

            // STEP 2: Get the bpf_program object for the main program
            bpf_object__for_each_program(prog, skel->obj) {{
                bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
                bpf_program__set_log_level(prog, 1); // optional: verbose logs
            }}

            // STEP 3: Load the program (this will trigger verifier log output)
            err = {self.name}__load(skel);
            fprintf(
		stderr,
		"--- Verifier log start ---\\n"
		"%s\\n"
		"--- Verifier log end ---\\n",
		log_buf
		);
            if (err) {{
                fprintf(stderr, "Failed to load BPF skeleton: %d\\n", err);
                {self.name}__destroy(skel);
                return 1;
            }}

            printf("BPF program loaded successfully.\\n");

            {self.name}__destroy(skel);
            return 0;
        }}

        """
        with open(self.loader_src, "w") as f:
            f.write(loader_code)
        logger.info(f"Generated loader at {self.loader_src}")
