# GraphQL-Scripts

This repository contains a set of small utilities to help with security testing and exploration of GraphQL endpoints.

Included tools
- qGen — interactive Query Generator: lists schema methods and generates full GraphQL queries (selection sets) for a chosen method.
- effuzz — Endpoint Fuzzer: enumerates query/mutation names from a schema and performs lightweight requests to identify methods you can call (ffuf-like for GraphQL).
- sqli — SQLi Detector helper: probes string arguments for SQL injection indicators and writes sqlmap marker files for reproducible testing.

Quick notes
- Tools accept an introspection JSON file via `--introspection`.
- If `--introspection` is omitted, `qGen` and `effuzz` can fetch the schema automatically from `--url` (requires the `requests` package). Automatic introspection is saved by default to `introspection_schema.json` (disable with `--no-save-introspection`).
- Use these tools only on systems for which you have explicit authorization.

Requirements
- Python 3.7+
- For automatic introspection / HTTP requests: pip install requests

Basic workflow (recommended)
1. Use `effuzz` to quickly determine which methods the current session can call (permission discovery).
2. Use `qGen` to generate a full query for an interesting method and paste the result into your GraphQL client (Burp, Postman, GraphiQL, etc.).
3. Optionally use the `sqli` helper to target string arguments for SQLi checks and produce sqlmap marker files.

effuzz — quick example
- Run with a saved introspection file:
```shell
python3 effuzz/effuzz.py --introspection /path/to/introspection_schema.json --url https://example.com/graphql
```

- Example (sanitized) sample output:
```text
[✓] Introspection loaded (120 queries, 8 mutations)
------------------------------------------------------------
getAllTests         [Status: 401] [Size: 32]  [Words: 5]  [Lines: 1]
getAllUsers         [Status: 400] [Size: 261] [Words: 25] [Lines: 1]   # malformed query -> server accepted request (likely allowed)
getAllConfigs       [Status: 200] [Size: 48]  [Words: 15] [Lines: 1]   # likely accessible
------------------------------------------------------------
(Use --debug to dump full responses)
```

What to infer from effuzz output
- 401 / 403: authentication/authorization required.
- 400: GraphQL often returns 400 for malformed queries; if the server returns 400 rather than 401, it usually indicates your request reached the server (the method exists and you may have permission).
- 200: successful request — inspect the body for `data` or `errors`.

qGen — quick example
- Run with a saved introspection file:
```shell
python3 qGen/qGen.py --introspection /path/to/introspection_schema.json
```

- Interactive session (sanitized):
```text
qGen $ listMethods
 [1] getAllUsers
 [2] getUserById

qGen $ use getAllUsers
# The full query is printed and saved to queries/getAllUsers.txt
```

Notes about qGen
- The `use` command selects a method and immediately generates & saves the full query (no separate `genQuery` step).
- Generated queries are saved in the `queries/` directory.

sqli helper — quick example
- Install requirements (if provided) or at minimum:
```bash
pip install requests
```

- Run (headers passed as JSON string is one supported way; consult script help for options):
```bash
python3 sqli/sqli_detector.py https://example.com/graphql '{"Authorization":"Bearer TOKEN"}'
```

- Sample (sanitized) output:
```text
VULNERABLE PARAMETER: username (field: user)
Evidence: Baseline != Attack (baseline {"data": {"user": null}}, attack {"data": {"user": {"uuid": "1"}}})
Recommended sqlmap command:
sqlmap -r 'repro-payloads/user_username_<timestamp>_<id>_marker.http' -p "JSON[query]" --batch --skip-urlencode --parse-errors --random-agent
```

Security & ethics
- These tools actively probe targets; run them only on systems you are authorized to test.
- Inspect any generated marker files before running sqlmap or other automated tooling.
