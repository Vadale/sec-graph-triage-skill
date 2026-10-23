# Walkthrough: a reported SQL flow

This documentation-only interpretation uses the public synthetic
[SARIF report](findings.sarif) and [source files](project/). It is not a new scanner
result, a real application assessment or a held-out evaluation.

1. **Reported claim:** `demo/sql-query-concatenation` asks whether an identifier
   reaches a concatenated query. Its reported path has three steps:
   `orders.py:2`, `orders.py:3`, `database.py:3`.
2. **Current source observation:** [orders.py](project/orders.py) reads
   `params["order_id"]` and passes it to `database.fetch`. In
   [database.py](project/database.py), line 2 concatenates `order_id` into a query;
   line 3 passes that query to `connection.execute`.
3. **What collection establishes:** the selected files and code windows exist
   under the chosen root at collection time. The bundle includes hashes for those
   bytes and preserves the three reported steps. The sample report supplies no
   scan-snapshot digest, so it cannot establish identity with the original scan.
4. **What remains open:** the example supplies no actual HTTP route, authorization
   checks, production wiring, input restrictions or executing database fixture.
   A call path in a report is not proof that a real attacker can reach it.
5. **Next useful check:** inspect the actual caller and database API in an
   authorized application. If the relevant path exists, verify how untrusted
   values are constrained and whether the query uses parameter binding. Evaluate
   any proposed change with a focused test; no fix is applied by this example.

Reproduce collection with the command in the [README](../README.md). Exit 0 refers
to collection only. Do not execute the deliberately unsafe sample as an application.
