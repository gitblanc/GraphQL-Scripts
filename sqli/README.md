```markdown
# GraphQL SQLi Detector (sqli_detector.py)

A compact GraphQL SQL injection mini-detector (Python). This script performs GraphQL introspection, attempts a set of SQLi-like payloads against candidate string arguments, and writes reproducible marker `.http` files for use with sqlmap. The detector includes heuristics to reduce false positives and attempts to populate required arguments using values extracted from simple queries.

Key capabilities
- Performs GraphQL introspection to discover Query fields and their arguments.
- Attempts to extract real values from simple queries (tokens, keys, names) to use as baseline or to fill required arguments.
- Tests string-like arguments with a curated set of SQLi payloads.
- Detects SQL error messages in GraphQL error responses.
- Detects response differences (baseline vs attack), NULL-on-attack, and other signals.
- Writes reproducible `.http` marker files in repro-payloads/ where the vulnerable value is replaced by `*`.
- Produces a recommended sqlmap command for confirmed findings.
- Adds confirmation rules to reduce false positives (report only on strong evidence).

What the detector does (high-level)
1. Runs GraphQL introspection to obtain schema types and Query fields.
2. Tries to extract values from simple, argument-less queries (e.g., lists of objects) to collect tokens / names that may help construct valid requests.
3. For each field with string-like arguments:
   - Builds a working baseline by trying a few combinations of plausible values for other args.
   - Sends curated SQLi-like payloads in the target argument.
   - Skips results that are simple GraphQL syntax errors.
   - Detects SQL error messages, response differences, and null-on-attack.
   - If a required argument is missing, attempts to fill it from extracted values.
4. For confirmed signals, writes a marker `.http` file with the attack request (vulnerable value replaced by `*`) and recommends a sqlmap command.

Output
- Human-readable findings printed to stdout (colored if colorama is installed).
- Repro marker files in `repro-payloads/` for each finding; filenames include a timestamp and short hash to avoid collisions.
- Each finding includes:
  - field and argument name
  - evidence (error message or description)
  - marker request path
  - recommended sqlmap command (uses `-r <marker>` and `-p "JSON[query]"`)

Example output (sanitized)
```text
[*] Running introspection on https://example.com/graphql
[+] Baseline for user.email works with args: {'id': '123'}
[!] Found 1 potential SQL injection findings:

[1] SQL_ERROR_IN_RESPONSE: user.email
    Arguments used: {'id': '123', 'email': "' OR 1=1--"}
    Evidence: Syntax error near '...' (truncated)
    Marker request: repro-payloads/user_email_20251215T103000Z_1a2b3c4d_marker.http
    Recommended sqlmap command:
    sqlmap --level 5 --risk 3 -r 'repro-payloads/user_email_20251215T103000Z_1a2b3c4d_marker.http' -p "JSON[query]" --batch --skip-urlencode --parse-errors --random-agent
--------------------------------------------------------------------------------
```

Marker (.http) files
- Generated marker files are complete HTTP POST requests to the GraphQL endpoint with a JSON body where the vulnerable value is replaced by `*`. Example body:
```http
POST /graphql HTTP/1.1
Host: example.com
Content-Type: application/json
Authorization: Bearer TOKEN

{"query":"query { user(id: \"123\") { email } }"}
```
- The script will replace the attacked value with `*` in the JSON so sqlmap can inject into `JSON[query]` using `-p "JSON[query]"` and `-r <marker>`.

Detection heuristics / confirmation rules
To reduce noisy false positives, the detector reports a parameter only when one of the following holds:
- A clear SQL error is present in the GraphQL `errors` (matches common DB error signatures), OR
- Two or more distinct payloads produce evidence, OR
- A combination of strong signals (e.g., RESPONSE_DIFF + NULL_ON_ATTACK), OR
- A `NULL_ON_ATTACK` signal confirmed against a meaningful baseline.

Limitations
- The script uses a small, curated payload set — not exhaustive. Use sqlmap (the generated markers) to perform deeper automated testing.
- No concurrency or rate-limiting flags are exposed in this script. For large schemas or many fields, extend the script to support workers.
- The script attempts only simple strategies to populate required args. Complex authentication or nested input objects may not be fully supported.
- Time-based SQLi (delays) are not explicitly tested by default. Add time-based payloads and response timing checks to detect blind time-based SQLi.
- The script assumes the endpoint supports GraphQL introspection. If introspection is disabled, discovery will fail.

Extending / Contributions
- Add command-line flags for:
  - concurrency / workers
  - custom payload lists and strategies
  - retries / timeout / proxies / TLS options
- Expand payloads to include boolean- and time-based techniques.
- Improve extraction heuristics for nested types and input objects.
