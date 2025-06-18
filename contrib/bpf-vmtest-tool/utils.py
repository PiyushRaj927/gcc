import subprocess
import logging
from typing import Any

logger = logging.getLogger(__name__)


def run_command(cmd:list[str], **kwargs: Any):
    logger.debug(f"Running command: {' '.join(cmd)}")
    try:
        logger.debug(f"running command: {cmd}")
        result = subprocess.run(
            cmd,
            text=True,
            check=True,
            capture_output=True,
            shell=False,
            **kwargs,
        )
        logger.debug("Command stdout:\n" + result.stdout.strip())
        if result.stderr:
            logger.debug("Command stderr:\n" + result.stderr.strip())
        return result
    except subprocess.CalledProcessError as e:
        logger.error("Command failed with stdout:\n" + e.stdout.strip())
        logger.error("Command failed with stderr:\n" + e.stderr.strip())
        raise
