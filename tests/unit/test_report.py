"""Reporter tests (task 2.9, `ARCHITECTURE.md` 6.6): escaping, ordering, caps, fences.

Two properties carry the task. Attacker-controlled text (a path, a line of evidence) must not be
able to end a line, open a new annotation or escape a markdown fence (B11). And a flood of one
severity must not push another severity out of the output (B8).
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from tests.fixtures import assemble

from airlock.model import (
    EXIT_FINDINGS,
    EXIT_PASS,
    Finding,
    Mode,
    ScanReport,
    Severity,
)
from airlock.report import console, github, jsonout, summary


def _outside(text: str) -> str:
    """The document with every fenced block removed: the part GitHub renders as markup."""
    lines = text.split("\n")
    return "\n".join(
        line for line, fenced in zip(lines, _fence_states(text), strict=True) if not fenced
    )


def _fence_states(text: str) -> list[bool]:
    """Which lines sit inside a fenced block, so a test can ask about the rest of the document."""
    states: list[bool] = []
    open_fence: str | None = None
    for line in text.split("\n"):
        stripped = line.strip()
        if open_fence is None and stripped.startswith("`"):
            open_fence = stripped
            states.append(True)
            continue
        if open_fence is not None and stripped == open_fence:
            open_fence = None
            states.append(True)
            continue
        states.append(open_fence is not None)
    return states


DIGEST = "sha256:" + "a" * 64
# Built from fragments at call time (`AGENTS.md` 4): the `pat-` rules read every `.py` file in this
# repository as role `source`, so a committed literal of this line would be a finding on itself.
EVIDENCE = f"{assemble('ev', 'al')}({assemble('Buf', 'fer.from')}(a, 'base64'))"


def finding(
    severity: Severity = Severity.HIGH,
    rule_id: str = "cfg-dynamic-code",
    path: str = "postcss.config.mjs",
    line: int = 7,
    message: str = "remote code execution capability in a tooling config",
    evidence: str | None = EVIDENCE,
    **kwargs: object,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=line,
        roles=("tooling-config",),
        message=message,
        evidence=evidence,
        occurrence=0,
        fingerprint=DIGEST,
        suppressible=True,
        **kwargs,  # type: ignore[arg-type]
    )


def report(
    *findings: Finding, suppressed: tuple[Finding, ...] = (), **kwargs: object
) -> ScanReport:
    return ScanReport(
        tool_version=str(kwargs.pop("tool_version", "0.1.0")),
        mode=kwargs.pop("mode", Mode.PR),  # type: ignore[arg-type]
        repo_head=str(kwargs.pop("repo_head", "b" * 40)),
        base=kwargs.pop("base", "c" * 40),  # type: ignore[arg-type]
        files_indexed=int(kwargs.pop("files_indexed", 12)),
        files_scanned=int(kwargs.pop("files_scanned", 12)),
        files_skipped=dict(kwargs.pop("files_skipped", {})),  # type: ignore[arg-type]
        findings=findings,
        suppressed=suppressed,
        exit_code=int(kwargs.pop("exit_code", EXIT_FINDINGS)),
        **kwargs,  # type: ignore[arg-type]
    )


class TestConsole:
    def test_every_finding_is_one_line_in_report_order(self) -> None:
        text = console.render(
            report(
                finding(),
                finding(severity=Severity.WARN, rule_id="cfg-long-line", line=0),
            )
        )
        lines = text.rstrip("\n").split("\n")

        assert len(lines) == 3
        assert "HIGH" in lines[0] and "cfg-dynamic-code" in lines[0]
        assert "postcss.config.mjs:7" in lines[0]
        assert "WARN" in lines[1] and "cfg-long-line" in lines[1]
        assert lines[1].split()[1] == "cfg-long-line"
        assert "airlock:" in lines[2]

    def test_a_file_level_finding_has_no_line_suffix(self) -> None:
        text = console.render(report(finding(line=0)))

        assert "postcss.config.mjs " in text
        assert ":0" not in text

    def test_the_summary_line_counts_severities_and_skips(self) -> None:
        text = console.render(
            report(
                finding(),
                finding(severity=Severity.WARN, rule_id="cfg-a"),
                finding(severity=Severity.INFO, rule_id="cfg-b"),
                files_skipped={"skipped-oversize": 3, "submodule-present": 1},
            )
        )
        tail = text.rstrip("\n").split("\n")[-1]

        assert "1 HIGH · 1 WARN · 1 INFO" in tail
        assert "12 file(s) scanned" in tail
        assert "3 skipped-oversize, 1 submodule-present" in tail

    def test_suppressed_findings_are_said_to_be_hidden(self) -> None:
        text = console.render(report(finding(), suppressed=(finding(rule_id="cfg-c"),)))

        assert "1 suppressed" in text.rstrip("\n").split("\n")[-1]

    def test_a_clean_scan_is_one_summary_line(self) -> None:
        text = console.render(report(exit_code=EXIT_PASS))

        assert text.count("\n") == 1
        assert "0 HIGH · 0 WARN · 0 INFO" in text
        assert "nothing skipped" in text

    def test_a_newline_in_a_path_cannot_split_a_finding(self) -> None:
        text = console.render(report(finding(path="a\nb.js")))

        assert len(text.rstrip("\n").split("\n")) == 2
        assert "a b.js" in text

    def test_a_carriage_return_cannot_forge_a_second_line(self) -> None:
        text = console.render(report(finding(message="x\r\nairlock: forged summary")))

        assert len(text.rstrip("\n").split("\n")) == 2
        assert text.rstrip("\n").split("\n")[-1].startswith("airlock: 1 HIGH")


class TestGithubEscaping:
    def test_property_escaping_covers_all_five_characters(self) -> None:
        assert github.escape_property("100%:,") == "100%25%3A%2C"
        assert github.escape_property("a\rb\nc") == "a%0Db%0Ac"

    def test_data_escaping_leaves_the_two_property_only_characters_alone(self) -> None:
        assert github.escape_data("a:,b") == "a:,b"
        assert github.escape_data("50%") == "50%25"

    def test_a_percent_is_escaped_before_the_others_so_nothing_double_decodes(self) -> None:
        # Escaping `:` first and `%` second would turn "%3A" into "%253A" the other way round.
        assert github.escape_property("%3A") == "%253A"


class TestGithubAnnotations:
    def test_high_is_annotated_before_every_warn(self) -> None:
        text = github.render(
            report(
                finding(),
                finding(severity=Severity.WARN, rule_id="cfg-w"),
            )
        )
        lines = text.rstrip("\n").split("\n")

        assert lines[0].startswith("::error ")
        assert lines[1].startswith("::warning ")

    def test_an_annotation_carries_file_line_and_title(self) -> None:
        text = github.render(report(finding()))

        assert text.startswith("::error file=postcss.config.mjs,line=7,title=cfg-dynamic-code::")

    def test_a_file_level_annotation_omits_the_line(self) -> None:
        assert "line=" not in github.render(report(finding(line=0)))

    def test_info_becomes_a_notice_rather_than_nothing(self) -> None:
        assert github.render(report(finding(severity=Severity.INFO, rule_id="cfg-i"))).startswith(
            "::notice "
        )

    def test_a_newline_in_a_message_cannot_forge_a_second_annotation(self) -> None:
        payload = "real\r\n::error file=innocent.js,line=1,title=pwned::forged"
        text = github.render(report(finding(message=payload)))
        lines = text.rstrip("\n").split("\n")

        assert len(lines) == 1
        assert lines[0].startswith(
            "::error file=postcss.config.mjs,line=7,title=cfg-dynamic-code::real%0D%0A"
        )
        assert lines[0].count("\n") == 0

    def test_a_colon_or_comma_in_a_path_cannot_break_the_property_list(self) -> None:
        text = github.render(report(finding(path="a:b,c.js")))

        assert "file=a%3Ab%2Cc.js" in text

    def test_a_title_cannot_close_its_own_property(self) -> None:
        text = github.render(report(finding(rule_id="cfg-x")))
        assert text.count("title=") == 1

    def test_each_severity_is_capped_and_the_withheld_count_is_said(self) -> None:
        highs = tuple(finding(rule_id=f"cfg-h{i}", path=f"h{i}.js") for i in range(60))
        text = github.render(report(*highs))
        lines = text.rstrip("\n").split("\n")

        assert len(lines) == github.ANNOTATIONS_PER_LEVEL
        assert lines[-1].startswith("::error title=airlock::")
        assert "51 HIGH finding(s) are not annotated" in lines[-1]

    def test_a_warn_flood_cannot_push_a_high_out_of_the_output(self) -> None:
        """B8 through the annotation cap: the surviving annotations are the HIGHs."""
        flooded = [finding()] + [
            finding(severity=Severity.WARN, rule_id=f"cfg-w{i}", path=f"w{i}.js")
            for i in range(200)
        ]
        text = github.render(report(*flooded))

        assert "::error " in text
        assert text.rstrip("\n").split("\n")[0].startswith("::error ")
        assert text.count("::error ") == 1

    @pytest.mark.parametrize(
        ("prefix", "rule_prefix"),
        [
            ("::error ", "cfg-high"),
            ("::warning ", "cfg-warn"),
            ("::notice ", "cfg-info"),
        ],
    )
    def test_no_level_writes_more_lines_than_a_step_can_keep(
        self, prefix: str, rule_prefix: str
    ) -> None:
        """The measured budget (0.9): 10 annotations of each level survive one step.

        Everything past that is discarded by the runner, including the note that names what was
        withheld, so the cap has to leave a slot for the note rather than spend all of them.
        """
        flooded = [
            finding(severity=severity, rule_id=f"{rule_prefix}-{i}", path=f"f{i}.js")
            for severity, rule_prefix in zip(
                Severity, ("cfg-high", "cfg-warn", "cfg-info"), strict=True
            )
            for i in range(100)
        ]
        text = github.render(report(*flooded, suppressed=(finding(),)))

        assert sum(1 for line in text.split("\n") if line.startswith(prefix)) == (
            github.ANNOTATIONS_PER_LEVEL
        )

    def test_the_suppression_note_shares_the_notice_budget_with_the_info_cap(self) -> None:
        """Two `::notice` lines are metadata, not findings: an INFO flood must not cost them."""
        infos = [
            finding(severity=Severity.INFO, rule_id=f"cfg-i{i}", path=f"i{i}.js") for i in range(40)
        ]
        text = github.render(report(*infos, suppressed=(finding(),)))
        notices = [line for line in text.split("\n") if line.startswith("::notice ")]

        assert len(notices) == github.ANNOTATIONS_PER_LEVEL
        assert any("are not annotated above" in line for line in notices)
        assert any("hidden by the trusted airlock.toml" in line for line in notices)

    def test_an_empty_report_annotates_nothing(self) -> None:
        assert github.render(report(exit_code=EXIT_PASS)) == ""

    def test_suppressions_are_announced_without_naming_a_finding(self) -> None:
        text = github.render(report(suppressed=(finding(),)))
        expected = (
            "::notice title=airlock::1 finding(s) are hidden by the trusted airlock.toml; "
            "the JSON output names each one and its reason.\n"
        )

        assert text == expected


class TestDocumentedLimits:
    """Task 0.9 replaced the guessed caps with a measured boundary. Guard both halves.

    The check fails if the design text loses the numbers the constants are justified by, and if a
    cap grows past what a step renders, which is the failure the old 50/25 values had.
    """

    def test_the_recorded_limits_are_still_cited_where_the_caps_come_from(self) -> None:
        root = Path(__file__).resolve().parents[2]
        reporters = (
            (root / "ARCHITECTURE.md")
            .read_text(encoding="utf-8")
            .split("### 6.6 Reporters\n", 1)[1]
            .split("\n## ", 1)[0]
        )

        assert "[Unverified: exact limits" not in reporters
        assert "10 warning and 10 error" in reporters
        assert "1 MiB per step" in reporters
        assert "41016320957" in reporters

    def test_every_level_leaves_a_slot_for_its_own_accounting_note(self) -> None:
        assert github.HIGH_ANNOTATIONS + 1 == github.ANNOTATIONS_PER_LEVEL
        assert github.WARN_ANNOTATIONS + 1 == github.ANNOTATIONS_PER_LEVEL
        assert github.INFO_ANNOTATIONS + 2 == github.ANNOTATIONS_PER_LEVEL


class TestJSON:
    def test_the_payload_is_the_whole_report_with_stable_keys(self) -> None:
        text = jsonout.render(
            report(finding(), files_skipped={"skipped-oversize": 2}, suppressed=(finding(),))
        )
        payload = json.loads(text)

        assert payload["mode"] == "pr"
        assert payload["exit_code"] == EXIT_FINDINGS
        assert payload["files_skipped"] == {"skipped-oversize": 2}
        assert len(payload["findings"]) == 1 and len(payload["suppressed"]) == 1
        assert payload["findings"][0]["severity"] == "high"
        assert payload["findings"][0]["fingerprint"] == DIGEST

    def test_severities_are_labels_not_integers(self) -> None:
        one = finding(severity=Severity.WARN, rule_id="cfg-w")
        payload = json.loads(jsonout.render(report(one)))

        assert payload["findings"][0]["severity"] == "warn"

    def test_two_renders_of_one_report_are_the_same_bytes(self) -> None:
        first = jsonout.render(report(finding(), files_skipped={"b": 1, "a": 2}))
        second = jsonout.render(report(finding(), files_skipped={"a": 2, "b": 1}))

        assert first == second
        assert list(json.loads(first)["files_skipped"]) == ["a", "b"]

    def test_the_suppression_reason_survives_serialization(self) -> None:
        hidden = replace(finding(), suppressed_by="audited upstream")
        payload = json.loads(jsonout.render(report(suppressed=(hidden,))))

        assert payload["suppressed"][0]["suppressed_by"] == "audited upstream"

    def test_evidence_stays_a_string_and_null_stays_null(self) -> None:
        payload = json.loads(
            jsonout.render(report(finding(evidence=None), finding(rule_id="cfg-b", evidence="x")))
        )
        excerpts = [item["evidence"] for item in payload["findings"]]

        assert None in excerpts
        assert "x" in excerpts
        assert all(item is None or isinstance(item, str) for item in excerpts)


class TestSummaryFences:
    def test_three_backticks_is_the_ordinary_fence(self) -> None:
        assert summary.fence_for(["a line of code"]) == "```"

    def test_the_fence_outlives_the_longest_run(self) -> None:
        assert len(summary.fence_for(["```` four ``"])) == 5

    def test_the_fence_suits_every_block_inside(self) -> None:
        assert len(summary.fence_for(["short", "`````` six"])) == 7

    def test_evidence_cannot_close_its_fence_and_become_a_heading(self) -> None:
        payload = "```\n# Deploy the key to prod\nhttps://evil.invalid"
        text = summary.render(report(finding(evidence=payload)))
        lines = text.split("\n")

        fences = [line for line in lines if line.startswith("`")]
        assert all(len(line) >= 4 for line in fences)
        assert "# Deploy the key to prod" in text
        assert not any(line.strip() == "```" for line in lines)

    def test_a_newline_in_evidence_cannot_escape_the_block(self) -> None:
        text = summary.render(report(finding(evidence="a\nb")))

        assert "a b" in text
        assert "\n\nb\n" not in text

    def test_a_path_cannot_render_as_a_link(self) -> None:
        text = summary.render(report(finding(path="[click here](https://evil.invalid)")))

        assert r"\[click here\]" in text
        assert "[click here](https://evil.invalid)" not in text

    def test_a_message_cannot_start_a_table_row(self) -> None:
        text = summary.render(report(finding(message="x | y\n| HIGH | cfg-fake | fake | fake |")))

        assert "\\|" in text
        assert "| HIGH | cfg-fake |" not in text

    def test_a_backtick_in_a_path_cannot_open_markup(self) -> None:
        text = summary.render(report(finding(path="`a`")))

        assert r"\`a\`" in text


class TestSummaryContent:
    def test_every_high_is_listed_and_the_rest_are_counted(self) -> None:
        flooded = [finding()] + [
            finding(severity=Severity.WARN, rule_id=f"cfg-w{i}", path=f"w{i}.js")
            for i in range(500)
        ]
        text = summary.render(report(*flooded))

        assert "cfg-dynamic-code" in text
        assert "cfg-w0" not in text
        assert "1 HIGH" in text and "500 WARN" in text

    def test_B8_a_warn_flood_keeps_every_high_visible(self) -> None:
        highs = [finding(path=f"h{i}.js", rule_id=f"cfg-h{i}") for i in range(20)]
        floods = [
            finding(severity=Severity.WARN, path=f"w{i}.js", rule_id=f"cfg-w{i}")
            for i in range(400)
        ]
        text = summary.render(report(*highs, *floods))

        for index in range(20):
            assert f"cfg-h{index}" in text
        assert "20 HIGH" in text

    def test_skipped_files_get_their_own_table(self) -> None:
        text = summary.render(report(exit_code=EXIT_PASS, files_skipped={"nul-in-text": 4}))

        assert "| nul-in-text | 4 |" in text

    def test_nothing_skipped_says_so(self) -> None:
        assert "No file was skipped." in summary.render(report())

    def test_no_high_findings_says_so_rather_than_rendering_an_empty_table(self) -> None:
        text = summary.render(report(finding(severity=Severity.WARN, rule_id="cfg-w")))

        assert "No HIGH finding." in text

    def test_no_evidence_renders_no_fence(self) -> None:
        text = summary.render(report(finding(evidence=None)))

        assert "### Evidence" not in text

    def test_long_evidence_is_truncated(self) -> None:
        text = summary.render(report(finding(evidence="x" * 5_000)))

        assert "x" * summary.SUMMARY_EVIDENCE_CHARS in text
        assert "x" * (summary.SUMMARY_EVIDENCE_CHARS + 1) not in text

    def test_the_document_names_the_mode_and_exit_code(self) -> None:
        text = summary.render(report(mode=Mode.PUSH, exit_code=EXIT_FINDINGS))

        assert "Mode `push`" in text and "exit 1" in text

    def test_a_clean_scan_still_produces_a_summary(self) -> None:
        text = summary.render(report(exit_code=EXIT_PASS, files_skipped={"skipped-oversize": 1}))

        assert text.startswith("# Airlock")
        assert "0 HIGH" in text

    @pytest.mark.parametrize(
        "payload",
        ["```", "``````", "a```b", "<script>", "[x](y)", "| HIGH | cfg-fake | x | y |"],
    )
    def test_attacker_text_never_reaches_the_rendered_part_of_the_document(
        self, payload: str
    ) -> None:
        """Evidence keeps its text, inside a fence; outside it nothing is markup (B11)."""
        body = summary.render(report(finding(evidence=payload, path=payload)))

        assert payload not in _outside(body)
