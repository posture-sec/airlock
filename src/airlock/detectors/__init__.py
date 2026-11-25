"""Detector registry: a plain list of in-tree detector functions.

Third-party detector plugins are not supported; loading external code would defeat the
trust model (ARCHITECTURE.md 6.3). `DETECTORS` stays a literal tuple so a scan with no
registered detectors is a config error rather than a pass, and `DETECTOR_NAMES` is what the
rule loader cross-checks a `builtin:<name>` pointer against.

Detectors yield `PendingFinding`; the runner assigns occurrence indices and builds Findings,
because a detector cannot know an occurrence number.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from ..fingerprint import PendingFinding
from ..model import ScanContext
from . import (
    cargo_vectors,
    ci_surface,
    config_role,
    npm_registry,
    stellar_seed,
    submodules,
    wasm_manifest,
)
from .native_binary import native_binary

Detector = Callable[[ScanContext], Iterable[PendingFinding]]

DETECTORS: tuple[Detector, ...] = (
    cargo_vectors.run,
    ci_surface.run,
    config_role.run,
    native_binary,
    npm_registry.run,
    stellar_seed.run,
    submodules.run,
    wasm_manifest.run,
)

#: Bare names, as they appear after the `builtin:` prefix in a rule file.
DETECTOR_NAMES: frozenset[str] = frozenset(
    {
        "cargo_vectors",
        "ci_surface",
        "config_role",
        "native_binary",
        "npm_registry",
        "stellar_seed",
        "submodules",
        "wasm_manifest",
    }
)
