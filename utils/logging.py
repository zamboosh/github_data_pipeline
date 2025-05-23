import os
import sys
from datetime import datetime
from pathlib import Path

from loguru import logger


def configure_logging(log_level=None, log_file=None):
    """
    Configure the logging system.

    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file, or None to use auto-generated name
    """
    # Get log level from environment if not provided
    if log_level is None:
        log_level = os.getenv("LOG_LEVEL", "INFO")

    # Remove default handler
    logger.remove()

    # Add console handler
    logger.add(sys.stderr, level=log_level)

    # Add file handler if requested
    if log_file is not None:
        log_path = Path(log_file)
    else:
        # Create logs directory if it doesn't exist
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)

        # Auto-generate log file name with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = logs_dir / f"github_pipeline_{timestamp}.log"

    logger.add(
        str(log_path),
        level=log_level,
        rotation="10 MB",
        retention="30 days",
        compression="zip",
    )

    logger.info(f"Logging configured with level {log_level}")
    logger.info(f"Log file: {log_path}")

    return logger
