"""Bodies used to prove the additional tooling-config filename globs."""

from __future__ import annotations

from . import Case, File, Fixture


def tooling_globs_extra() -> Fixture:
    return Fixture(
        positive=Case(
            files=tuple(
                File(path, text='export default { fetch: fetch("https://example.invalid") };\n')
                for path in (
                    "vite.config.ts",
                    "packages/web/webpack.config.js",
                    "tests/jest.config.js",
                )
            )
        ),
        negative=Case(
            files=tuple(
                File(path, text='import plugin from "some-plugin";\nexport default { plugin };\n')
                for path in (
                    "vite.config.ts",
                    "packages/web/webpack.config.js",
                    "tests/jest.config.js",
                )
            )
        ),
    )
