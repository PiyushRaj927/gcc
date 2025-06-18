import logging
import os
import shutil
import subprocess
from pathlib import Path
import re
from urllib.parse import urljoin
from urllib.request import urlretrieve
from typing import Optional, List
from dataclasses import dataclass

from config import ARCH, BASE_DIR, KCONFIG_REL_PATHS, KERNEL_TARBALL_PREFIX_URL
import utils

logger = logging.getLogger(__name__)
KERNELS_DIR = BASE_DIR / "kernels"


@dataclass
class KernelSpec:
    """Immutable kernel specification"""

    version: str
    arch: str = ARCH

    def __post_init__(self):
        self.major = self.version.split(".")[0]

    def __str__(self):
        return f"{self.version}-{self.arch}"

    @property
    def bzimage_path(self) -> Path:
        return KERNELS_DIR / f"bzImage-{self}"

    @property
    def tarball_path(self) -> Path:
        return KERNELS_DIR / f"linux-{self.version}.tar.xz"

    @property
    def kernel_dir(self) -> Path:
        return KERNELS_DIR / f"linux-{self.version}"


class KernelImage:
    """Represents a compiled kernel image"""

    def __init__(self, path: Path):
        if not isinstance(path, Path):
            path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Kernel image not found: {path}")

        self.path = path

    def __str__(self):
        return str(self.path)


class KernelCompiler:
    """Handles complete kernel compilation process including download and build"""

    def compile_from_version(self, spec: KernelSpec) -> KernelImage:
        """Complete compilation process from kernel version"""
        if spec.bzimage_path.exists():
            logger.info(f"Kernel {spec} already exists, skipping compilation")
            return KernelImage(spec.bzimage_path)

        try:
            self._download_source(spec)
            self._extract_source(spec)
            self._configure_kernel(spec)
            self._compile_kernel(spec)
            self._copy_bzimage(spec)

            logger.info(f"Successfully compiled kernel {spec}")
            return KernelImage(spec.bzimage_path)

        except Exception as e:
            logger.error(f"Failed to compile kernel {spec}: {e}")
            raise
        finally:
            # Always cleanup temporary files
            self._cleanup(spec)

    def _download_source(self, spec: KernelSpec) -> None:
        """Download kernel source tarball"""
        if spec.tarball_path.exists():
            logger.info(f"Tarball already exists: {spec.tarball_path}")
            return

        url_suffix = f"v{spec.major}.x/linux-{spec.version}.tar.xz"
        url = urljoin(KERNEL_TARBALL_PREFIX_URL, url_suffix)

        logger.info(f"Downloading kernel from {url}")
        spec.tarball_path.parent.mkdir(parents=True, exist_ok=True)
        urlretrieve(url, spec.tarball_path)
        logger.info("Kernel source downloaded")

    def _extract_source(self, spec: KernelSpec) -> None:
        """Extract kernel source tarball"""
        logger.info(f"Extracting kernel source to {spec.kernel_dir}")
        spec.kernel_dir.mkdir(parents=True, exist_ok=True)

        utils.run_command(
            [
                "tar",
                "-xf",
                str(spec.tarball_path),
                "-C",
                str(spec.kernel_dir),
                "--strip-components=1",
            ]
        )

    def _configure_kernel(self, spec: KernelSpec) -> None:
        """Configure kernel with provided config files"""
        config_path = spec.kernel_dir / ".config"

        with open(config_path, "wb") as kconfig:
            for config_rel_path in KCONFIG_REL_PATHS:
                config_abs_path = spec.kernel_dir / config_rel_path
                if config_abs_path.exists():
                    with open(config_abs_path, "rb") as conf:
                        kconfig.write(conf.read())

        logger.info("Updated kernel configuration")

    def _compile_kernel(self, spec: KernelSpec) -> None:
        """Compile the kernel"""
        logger.info(f"Compiling kernel in {spec.kernel_dir}")
        old_cwd = os.getcwd()

        try:
            os.chdir(spec.kernel_dir)
            utils.run_command(["make", "olddefconfig"])
            utils.run_command(["make", f"-j{os.cpu_count()}", "bzImage"])
        except subprocess.CalledProcessError as e:
            logger.error(f"Kernel compilation failed: {e}")
            raise
        finally:
            os.chdir(old_cwd)

    def _copy_bzimage(self, spec: KernelSpec) -> None:
        """Copy compiled bzImage to final location"""
        src = spec.kernel_dir / "arch/x86/boot/bzImage"
        dest = spec.bzimage_path
        dest.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(src, dest)
        logger.info(f"Stored bzImage at {dest}")

    def _cleanup(self, spec: KernelSpec) -> None:
        """Clean up temporary files"""
        if spec.tarball_path.exists():
            spec.tarball_path.unlink()
            logger.info("Removed tarball")

        if spec.kernel_dir.exists():
            shutil.rmtree(spec.kernel_dir)
            logger.info("Removed kernel source directory")


class KernelManager:
    """Main interface for kernel management"""

    def __init__(self):
        self.compiler = KernelCompiler()

    def get_kernel_image(
        self,
        version: Optional[str] = None,
        kernel_image_path: Optional[str] = None,
        arch: str = ARCH,
    ) -> KernelImage:
        """Get kernel image from version or existing file"""

        # Validate inputs
        if not version and not kernel_image_path:
            raise ValueError("Must provide either 'version' or 'kernel_image_path'")

        if version and kernel_image_path:
            raise ValueError("Provide only one of 'version' or 'kernel_image_path'")

        # Handle existing kernel image
        if kernel_image_path:
            path = Path(kernel_image_path)
            if not path.exists():
                raise FileNotFoundError(f"Kernel image not found: {kernel_image_path}")
            return KernelImage(path)

        # Handle version-based compilation
        if version:
            spec = KernelSpec(version=version, arch=arch)
            return self.compiler.compile_from_version(spec)

    def list_available_kernels(self) -> List[str]:
        """List all available compiled kernels"""
        if not KERNELS_DIR.exists():
            return []

        kernels = []
        for file in KERNELS_DIR.glob("bzImage-*"):
            match = re.match(r"bzImage-(.*)", file.name)
            if match:
                kernels.append(match.group(1))

        return sorted(kernels)
