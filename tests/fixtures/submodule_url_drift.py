"""Synthetic gitlink and `.gitmodules` entries for submodule URL drift."""

from __future__ import annotations

from . import Case, File, Fixture


def submodule_url_drift() -> Fixture:
    gitlink = File("vendor/dep", skip_reason="submodule")
    positive_modules = (
        '[submodule "dep"]\npath = "vendor/dep"\nurl = "https://mirror.invalid/dep.git"\n'
    )
    negative_modules = (
        '[submodule "dep"]\npath = "vendor/dep"\nurl = "https://github.com/owner/dep.git"\n'
    )
    return Fixture(
        positive=Case(files=(File(".gitmodules", text=positive_modules), gitlink)),
        negative=Case(files=(File(".gitmodules", text=negative_modules), gitlink)),
    )


BUILDERS = {"submodule_url_drift": submodule_url_drift}
