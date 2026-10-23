# Source and adaptation

Derived from selected normalization, physical-location and source-window design
in **sec-graph**, revision `964e3cb047ad7a087033cd635709097a10fd86b4`,
Copyright (c) 2026 Alessandro Vadala, MIT. The complete MIT terms are in
[LICENSE](../LICENSE); keep them with redistributed portions.

| Source | SHA-256 | Adaptation |
|---|---|---|
| `secgraph/ingest/normalize.py` | `40fa68b8d0bf4cadcbda357bbb1e7a0e7bcb13332c1dffa89f63bf2713d77591` | Reworked local URI/base resolution; explicit mapping replaces suffix rescue |
| `secgraph/ingest/sarif.py` | `64b66726f446b40b27ad360b2cd75149977c4237de3a439bdf6405ee0f796504` | Reworked physical-location parsing; preserve flows, threads and gaps |
| `secgraph/mcp_view.py` | `8878693c95e09b979810a401373b408a8bef226de0f577954d7ef8591d1dbabc` | Current-window/hash concept; new explicit-root, bounded no-follow read implementation |

No full secgraph package, graphify, visualization, taint/auth rule engine or MCP
server is bundled. Their runtime dependencies are not required by this helper.
The helper is a standalone adaptation; upstream analysis/benchmark results are
not evidence of this skill's accuracy, coverage, efficiency or security.
