#!/usr/bin/env python3
import json
import os
import sys
import argparse
import textwrap
from typing import Dict, Any, List, Optional

# Try to import requests; if missing, we'll show a helpful message when needed
try:
    import requests
except Exception:
    requests = None

# ANSI COLORS
RED = "\033[31m"
GREY = "\033[90m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"

def print_banner():
    print(f"""
{YELLOW}
 ██████╗  ██████╗ ███████╗███╗   ██╗
██╔═══██╗██╔════╝ ██╔════╝████╗  ██║
██║   ██║██║  ███╗█████╗  ██╔██╗ ██║
██║▄▄ ██║██║   ██║██╔══╝  ██║╚██╗██║
╚██████╔╝╚██████╔╝███████╗██║ ╚████║
 ╚══▀▀═╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝ v1.0
{RESET}

{CYAN}made by gitblanc — https://github.com/gitblanc/QGen{RESET}

""")

def load_introspection():
    while True:
        path = input("Enter introspection JSON file path: ").strip()

        if not os.path.exists(path):
            print("❌ File not found. Try again.\n")
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            print("✅ Introspection successfully loaded.\n")
            return data
        except Exception as e:
            print(f"❌ Error reading JSON: {e}\n")

# Introspection query used when obtaining schema from endpoint
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args {
          name
          type { kind name ofType { kind name ofType { kind name } } }
        }
        type { kind name ofType { kind name } }
      }
    }
  }
}
"""

def parse_header_list(headers_list: List[str]) -> Dict[str, str]:
    """
    Convert list of 'Name: Value' strings to a dict (last wins for duplicates).
    """
    hdrs: Dict[str, str] = {}
    for h in headers_list or []:
        if ":" not in h:
            print(f"⚠️ Ignoring malformed header (expected 'Name: Value'): {h}")
            continue
        name, value = h.split(":", 1)
        hdrs[name.strip()] = value.strip()
    return hdrs

def perform_introspection_request(url: str, headers: Dict[str, str], timeout: int = 15) -> Optional[Dict[str, Any]]:
    """
    Perform a POST request to the GraphQL endpoint with the introspection query.
    Returns parsed JSON on success, or None on failure.
    """
    if requests is None:
        print("❌ The 'requests' library is required for automatic introspection. Install with: pip install requests")
        return None

    try:
        resp = requests.post(url, headers=headers, json={"query": INTROSPECTION_QUERY}, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"❌ HTTP error while requesting introspection: {e}")
        return None

    try:
        data = resp.json()
    except Exception as e:
        print(f"❌ Response is not valid JSON: {e}")
        return None

    if (isinstance(data, dict) and
        ((data.get("data") and isinstance(data["data"], dict) and "__schema" in data["data"]) or ("__schema" in data))):
        return data

    print("❌ Introspection response does not contain '__schema' (not a valid GraphQL introspection).")
    return None

def save_introspection_file(data: Dict[str, Any], path: str = "introspection_schema.json") -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"✅ Introspection saved to: {path}")
    except Exception as e:
        print(f"⚠️ Failed to save introspection to {path}: {e}")

# Extract query fields
def extract_graphql_queries(introspection):
    try:
        types = introspection["data"]["__schema"]["types"]
    except Exception:
        return []

    query_type_name = introspection["data"]["__schema"]["queryType"]["name"]
    query_type = next((t for t in types if t.get("name") == query_type_name), None)

    if not query_type:
        return []

    return query_type.get("fields", [])


# Follow NON_NULL / LIST / etc.
def resolve_type(t):
    while t.get("ofType") is not None:
        t = t["ofType"]
    return t


# Recursively build full field tree for the query
def build_field_tree(field_type, types, depth=0, visited=None):
    if visited is None:
        visited = set()

    field_type = resolve_type(field_type)

    # Some types might not have a name (e.g., scalars) - guard
    name = field_type.get("name")
    if name and name in visited:
        return ""

    if name:
        visited.add(name)

    if field_type.get("kind") != "OBJECT":
        return ""

    obj = next((t for t in types if t["name"] == field_type["name"]), None)
    if not obj or "fields" not in obj:
        return ""

    indent = "  " * depth
    result = ""

    for f in obj["fields"]:
        f_type = resolve_type(f["type"])
        f_name = f["name"]

        if f_type.get("kind") == "OBJECT":
            sub = build_field_tree(f["type"], types, depth + 1, visited.copy())
            result += f"{indent}{f_name} {{\n{sub}{indent}}}\n"
        else:
            result += f"{indent}{f_name}\n"

    return result

def save_query_to_file(method_name, query_text):
    # Ensure directory exists
    os.makedirs("queries", exist_ok=True)

    path = f"queries/{method_name}.txt"

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(query_text)
        print(f"📁 Query saved to: {path}\n")
    except Exception as e:
        print(f"❌ Error saving query: {e}")

def stringify_type(t):
    """Convert GraphQL type tree into a printable type string."""
    if not isinstance(t, dict):
        return "Unknown"
    if t.get("kind") == "NON_NULL":
        return f"{stringify_type(t['ofType'])}!"
    elif t.get("kind") == "LIST":
        return f"[{stringify_type(t['ofType'])}]"
    else:
        return t.get("name", "Unknown")

def generate_full_query(method_field, introspection):
    types = introspection["data"]["__schema"]["types"]

    # ---- Extract arguments ----
    args = method_field.get("args", [])
    variables = []
    call_args = []

    for a in args:
        var_name = a["name"]
        var_type = stringify_type(a["type"])
        variables.append(f"${var_name}: {var_type}")
        call_args.append(f"{var_name}: ${var_name}")

    # Build signature
    variables_str = f"({', '.join(variables)})" if variables else ""
    call_args_str = f"({', '.join(call_args)})" if call_args else ""

    # ---- Build field tree ----
    root_type = method_field["type"]
    fields_tree = build_field_tree(root_type, types, depth=2)

    # ---- Build final query ----
    return f"""
query {method_field['name']}{variables_str} {{
  {method_field['name']}{call_args_str} {{
{fields_tree}
  }}
}}
""".rstrip()


def print_help():
    print("""
Available commands:
  help               - Show this help message
  listMethods        - List all available GraphQL methods
  use <num|method>   - Select a method and immediately generate its full query
  exit               - Exit the application
""")


def interactive_console(methods, introspection):
    selected_method = None

    print("Type 'help' to see available commands.\n")

    while True:
        raw_cmd = input(f"{RED}Qgen ${RESET} ").strip()

        # --- PIPE SUPPORT ---
        if "|" in raw_cmd:
            left, _, right = raw_cmd.partition("|")
            cmd = left.strip()
            pipe_cmd = right.strip()

            if pipe_cmd.startswith("grep"):
                _, _, grep_text = pipe_cmd.partition("grep")
                grep_text = grep_text.strip().lower()
            else:
                print("❌ Unsupported pipe command.\n")
                continue
        else:
            cmd = raw_cmd
            pipe_cmd = None
        # ---------------------

        # MAIN COMMAND HANDLING
        if cmd == "help":
            output = """Available commands:
  help               - Show this help message
  listMethods        - List all available GraphQL methods
  use <num|method>   - Select a method and immediately generate its full query
  exit               - Exit the application
"""
            if pipe_cmd:
                output = "\n".join(
                    line for line in output.splitlines() if grep_text in line.lower()
                )
            print(output)

        elif cmd == "listMethods":
            lines = [f" [{i}] {m['name']}" for i, m in enumerate(methods, start=1)]

            if pipe_cmd:
                lines = [l for l in lines if grep_text in l.lower()]

            print("\n📌 Available methods:")
            for line in lines:
                print(line)
            print()

        elif cmd.startswith("use "):
            _, _, value = cmd.partition(" ")
            value = value.strip()

            if value.isdigit():
                idx = int(value) - 1
                if 0 <= idx < len(methods):
                    selected_method = methods[idx]
                    print(f"✔ Selected method: {selected_method['name']}\n")
                else:
                    print("❌ Invalid method number.\n")
                    continue
            else:
                match = next((m for m in methods if m["name"] == value), None)
                if match:
                    selected_method = match
                    print(f"✔ Selected method: {value}\n")
                else:
                    print("❌ Method not found.\n")
                    continue

            # Unified behavior: immediately generate the full query for the selected method
            try:
                query = generate_full_query(selected_method, introspection)
                print("\n----------------------------------------")
                print(f"{BLUE}{query}{RESET}")
                print("----------------------------------------\n")

                # Save the query automatically
                save_query_to_file(selected_method["name"], query)
            except Exception as e:
                print(f"❌ Error generating query: {e}\n")

        elif cmd == "exit":
            print("👋 Exiting...")
            break

        else:
            print("❌ Unknown command. Type 'help' for the command list.\n")


def main():
    print_banner()
    print("=== GraphQL Interactive CLI (extruder) ===\n")

    parser = argparse.ArgumentParser(description="GraphQL Introspection CLI Extruder")
    parser.add_argument(
        "--introspection",
        type=str,
        help="Path to introspection JSON file"
    )
    # New: endpoint URL to query introspection if --introspection is omitted
    parser.add_argument(
        "--url",
        type=str,
        help="GraphQL endpoint URL to perform introspection automatically if --introspection is not provided"
    )
    # Support repeated headers -H "Name: Value"
    parser.add_argument("-H", "--header", action="append", default=[], help="Additional HTTP header to include when performing automatic introspection. Format: 'Name: Value'")
    # Cookie file support (for automatic introspection)
    parser.add_argument("--cookie", help="File containing cookie in plain text (one line) to use when performing automatic introspection")
    # Saving option for automatic introspection
    parser.add_argument("--save-introspection", dest="save_introspection", action="store_true", help="Save automatic introspection to introspection_schema.json")
    parser.add_argument("--no-save-introspection", dest="save_introspection", action="store_false", help="Do not save automatic introspection to disk")
    parser.set_defaults(save_introspection=True)

    args = parser.parse_args()

    introspection = None

    # If provided via CLI file, try to load it directly
    if args.introspection:
        if os.path.exists(args.introspection):
            try:
                with open(args.introspection, "r", encoding="utf-8") as f:
                    introspection = json.load(f)
                print("✅ Introspection successfully loaded from CLI argument.\n")
            except Exception as e:
                print(f"❌ Error reading JSON: {e}\n")
                return
        else:
            print("❌ File path passed to --introspection does not exist.\n")
            return
    else:
        # Attempt to perform automatic introspection if --url provided
        if args.url:
            # Build headers: Content-Type + user provided headers + cookie (if provided)
            headers = {"Content-Type": "application/json"}
            extra_headers = parse_header_list(args.header)
            if args.cookie:
                if not os.path.exists(args.cookie):
                    print(f"❌ Cookie file not found: {args.cookie}\n")
                    return
                with open(args.cookie, "r", encoding="utf-8") as f:
                    cookie_value = f.read().strip()
                # Respect explicit Cookie header if user provided it via -H
                if "Cookie" not in extra_headers:
                    extra_headers["Cookie"] = cookie_value
            headers.update(extra_headers)

            print(f"[*] No --introspection provided; performing introspection query against {args.url} ...")
            result = perform_introspection_request(args.url, headers)
            if result is None:
                print("❌ Could not obtain introspection from endpoint. Falling back to interactive prompt.\n")
                introspection = load_introspection()
            else:
                introspection = result
                print("✅ Introspection obtained from endpoint.\n")
                if args.save_introspection:
                    save_introspection_file(introspection, path="introspection_schema.json")
        else:
            # Fall back to interactive prompt if no --url supplied
            introspection = load_introspection()

    methods = extract_graphql_queries(introspection)

    if not methods:
        print("❌ No GraphQL methods found in the introspection.")
        return

    interactive_console(methods, introspection)


if __name__ == "__main__":
    main()
