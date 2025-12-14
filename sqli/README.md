```markdown
# GraphQL SQLi Detector

Small helper script to detect basic SQL injection indicators in GraphQL endpoints and produce reproducible sqlmap marker files.

What it does
- Performs GraphQL introspection to enumerate Query fields and string arguments.
- Sends a curated set of SQLi-like payloads to candidate string arguments and looks for SQL error messages, notable response differences or nulls that may indicate injection.
- For each finding the script writes a marker `.http` file in `repro-payloads/` where the vulnerable value is replaced by `*`.
- Prints a recommended `sqlmap` command per finding that references the marker file and injects into `JSON[query]`.

Requirements
- Python 3.7+
- requests (HTTP client)

Install
```bash
pip install requests
# or, if a requirements file exists:
pip install -r sqli/requirements.txt
```

Usage
```bash
# Basic usage; headers passed as a JSON string (example)
python3 sqli/sqli_detector.py https://example.com/graphql '{"Authorization":"Bearer TOKEN"}'
```

Output format (sanitized example)

Below is a sample of the detector output with sensitive data redacted. Paths are shown as relative to the repository.

```text
$ python3 sqli/sqli_detector.py https://example.com/graphql
[*] Running introspection on https://example.com/graphql
VULNERABLE PARAMETER: username (field: user)
Evidence: Baseline != Attack (baseline {"data": {"user": null}}, attack {"data": {"user": {"uuid": "1"}}})
Recommended sqlmap command:
sqlmap -r 'repro-payloads/user_username_<timestamp>_<id>_marker.http' -p "JSON[query]" --batch --skip-urlencode --parse-errors --random-agent
--------------------------------------------------------------------------------
VULNERABLE PARAMETER: username (field: user)
Evidence: Baseline != Attack (baseline {"data": {"user": null}}, attack {"data": {"user": {"uuid": "3"}}})
Recommended sqlmap command:
sqlmap -r 'repro-payloads/user_username_<timestamp>_<id>_marker.http' -p "JSON[query]" --batch --skip-urlencode --parse-errors --random-agent
```
