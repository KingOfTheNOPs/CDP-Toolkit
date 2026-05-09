from __future__ import annotations

import os
from typing import Any

from rich.console import Console


_console = Console(stderr=True)
_verbose = os.environ.get("CDPTK_VERBOSE", "").lower() in {"1", "true", "yes", "on"}


def set_verbose(enabled: bool) -> None:
    global _verbose
    _verbose = enabled


def is_verbose() -> bool:
    return _verbose


def info(message: str, *values: Any) -> None:
    if _verbose:
        if values:
            message = message.format(*values)
        _console.print(f"[dim cyan]info[/dim cyan] {message}")


def warn(message: str, *values: Any) -> None:
    if values:
        message = message.format(*values)
    _console.print(f"[yellow]warn[/yellow] {message}")

