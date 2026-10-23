# Contributing

Open an issue with the smallest useful **synthetic or sanitized** reproduction,
what you expected, what happened, and your assistant/runtime versions. Include
only material you have permission to share. Do not upload private code, datasets,
project conversations, tokens or filled personal reports.

Keep changes focused on this skill's declared purpose. Preserve licenses and
attribution. Explain any new dependency or changed access boundary. Update usage
examples when behavior changes; distinguish reproducible checks from judgments
that still depend on the host model or study design.

Run `python -m unittest discover -s tests -v` from the repository root. Changes to
collection should include a small regression case and preserve explicit partial
results. Do not execute scanned projects as part of collection.
