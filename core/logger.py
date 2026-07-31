"""Centralized logging setup for Frida-ShieldBreaker.

Provides a single Rich-backed logger shared by the CLI and every core
module, plus a lightweight namespaced adapter so log lines can be
attributed to the JS agent module that emitted them (e.g. tls_inspector,
fs_monitor) when messages come back over the Frida IPC channel.
"""

from __future__ import annotations

import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

# Shared console instance so CLI output and log records render consistently.
console = Console()

_CONFIGURED = False


def setup_logging(
    verbose: bool = False,
    log_file: Path | None = None,
) -> logging.Logger:
    """Configure and return the root "shieldbreaker" logger.

    Safe to call multiple times; only the first call installs handlers.

    Args:
        verbose: Enable DEBUG-level output on the console handler.
        log_file: Optional path to additionally persist logs to disk.

    Returns:
        The configured `shieldbreaker` logger.
    """
    global _CONFIGURED
    logger = logging.getLogger("shieldbreaker")

    if _CONFIGURED:
        return logger

    logger.setLevel(logging.DEBUG)

    console_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_time=True,
        show_path=verbose,
        # Log message content is arbitrary (JS exception messages, native
        # library paths, Java array-type descriptors like
        # "[Ljava.lang.String;") and none of it is ours to control --
        # Rich markup parsing crashed on a literal "[...]" in a native
        # error message (MarkupError: closing tag '[...]' doesn't match
        # any open tag). We never rely on markup styling in our own log
        # calls (only main.py's separate console.print() does, a
        # different render path), so disabling it here is free.
        markup=False,
    )
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    logger.addHandler(console_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
            )
        )
        logger.addHandler(file_handler)

    logger.propagate = False
    _CONFIGURED = True
    return logger


def get_logger(namespace: str | None = None) -> logging.Logger:
    """Return a child logger, e.g. get_logger('loader') -> shieldbreaker.loader."""
    base = logging.getLogger("shieldbreaker")
    return base.getChild(namespace) if namespace else base
