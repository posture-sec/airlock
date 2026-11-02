# Security

Airlock is a security tool, so a flaw in it is a way to make a compromised repository look
clean. Report vulnerabilities in Airlock itself, not through a public issue.

## Reporting

Open a private security advisory at
<https://github.com/posture-sec/airlock/security/advisories/new>. Include the commit you
tested, the mode (`pr`, `push` or `full`), and the smallest repository or fixture that
shows the problem. Expect an acknowledgement within five business days.

Do not open a public issue, pull request or chat message that describes an unpatched
bypass. The bypass regression tests in `tests/bypass/` are fine to discuss once a fix is
merged.

## What counts

- A file, payload or repository that the scanner reads as clean when it should not.
- A way for scanned content to influence the scanner: executing, importing or evaluating it,
  or a regex that blocks a run (ReDoS).
- Policy, suppression or Wasm manifest read from the wrong source, so the change under scan
  can relax the rules applied to it.
- Evidence text escaping its rendering context in a step summary or annotation, or flooding
  a report.
- A supply-chain weakness in the tool itself: an unpinned Action, a workflow that can be
  edited by the pull request it gates, or an unattested release.

## What does not

- A finding on a repository scanned by Airlock. Report that to that repository.
- A false positive. Open a normal issue; suppressions are issued by the maintainer with a
  reason, not requested as a security matter.
- A vulnerable dependency in a scanned repository. Airlock audits release integrity and
  injection, not advisories.

## Hard guarantees

The trust model is `ARCHITECTURE_ESSENTIALS.md` 2 and 8. Two residual risks are documented
rather than solved: whoever can push workflow files can remove the scan, and a compromised
maintainer account can force-push history. Required status checks, hardware-key or passkey
2FA and a protected recovery address are the real controls; the org-side configuration is
tracked as task 1.3.

## Versions

Nothing is released yet. Pre-`v0.1.0` commits carry no security guarantees; `main` may be
replaced wholesale until the first attested tag.
