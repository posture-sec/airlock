"""Entry point for `python -m airlock`."""

from __future__ import annotations

import os
import sys

from .cli import main

if __name__ == "__main__":
    code = main()
    # `cli._emit` already flushed, so this catches the descriptor that closed between then and
    # here. The interpreter flushes stdout again on the way out, after `main` has returned and
    # past every handler in the process, and a pipe closed by `| head` makes that print
    # `Exception ignored in: <_io.TextIOWrapper ...>` over a report that was always correct.
    # Pointing descriptor 1 at the null device is what stops it: the bytes have nowhere to go.
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    raise SystemExit(code)
