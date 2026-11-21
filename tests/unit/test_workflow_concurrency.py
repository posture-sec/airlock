"""The CI workflow cancels superseded checks and bounds the checks job."""

from pathlib import Path

CI = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"


def test_ci_concurrency_and_timeout() -> None:
    text = CI.read_text(encoding="utf-8")
    assert (
        "concurrency:\n"
        "  group: ${{ github.workflow }}-${{ github.ref }}\n"
        "  cancel-in-progress: true" in text
    )
    assert "  checks:\n    runs-on: ubuntu-latest\n" in text
    assert (
        "    timeout-minutes: 30\n" in text.split("  checks:\n", 1)[1].split("  self-scan:", 1)[0]
    )
