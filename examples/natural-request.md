# Understand a scanner finding

Synthetic illustration using the bundled example, not a security certification.

## Input and natural request

Provide [findings.sarif](findings.sarif) and the selected [Python source](project/).

> Explain these findings against the code I have now. Prioritize what to inspect,
> cite supporting lines, and tell me which claims still need evidence.

## What the result should contain

- **Reported claim:** the scanner reports a path toward a concatenated query.
- **Current evidence:** cited excerpts from the selected source, with observed
  correspondence to the report stated separately.
- **Unknowns:** any unseen callers, input constraints or absent flow steps.
- **Next check:** a concrete way to resolve the important gap, rather than an
  unsupported safe/unsafe verdict.

The [existing walkthrough](triage-walkthrough.md) explains the bundled files.
The helper collects static evidence without running the target project. Its
completion is not proof of exploitability or proof that a finding is false.

## When to use another workflow

Running a new scanner or reviewing arbitrary code without SARIF is a different
task. Selecting public documentation is a publication-content review.
