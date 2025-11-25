# Endpoint Fuzzer

This script helps you check for methods you've got permissions in your GraphQL schema.

```shell
███████╗███████╗███████╗██╗   ██╗███████╗███████╗
██╔════╝██╔════╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝
█████╗  █████╗  █████╗  ██║   ██║  ███╔╝   ███╔╝ 
██╔══╝  ██╔══╝  ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
███████╗██║     ██║     ╚██████╔╝███████╗███████╗
╚══════╝╚═╝     ╚═╝      ╚═════╝ ╚══════╝╚══════╝
```

## Usage

>[!Important]
>You must have previously obtained the result of an introspection query and save it to a json file like `introspection_schema.json`.

- Basic command:

```shell
python3 effuzz.py --introspection /path/to/introspection_schema.json --url https://example.com/graphql
```

- If you have cookie and/or variables to anidate queries:

```shell
python3 effuzz.py --introspection /path/to/introspection_schema.json --url https://example.com/graphql --cookie /path/to/cookie.txt --variables /path/to/variables.json
```

- Enable debug mode to check petitions and responses:

```shell
python3 effuzz.py --introspection /path/to/introspection_schema.json --url https://example.com/graphql --debug
```

- Match exact reponse status codes:

```shell
python3 effuzz.py --introspection /path/to/introspection_schema.json --url https://example.com/graphql --mc 200,403
```

- Hide responses with matching status codes:

```shell
python3 effuzz.py --introspection /path/to/introspection_schema.json --url https://example.com/graphql --fc 200,403
```

## Available commands

- You can use the following commands:

```shell
  --introspection     Path to the introspection JSON file
  --url               GraphQL endpoint URL
  -s | --silent       Only show endpoints that DO NOT return 401
  --cookie            File containing cookie in plain text (one line)
  --variables         JSON file with variables for the payload
  --debug             Show full request and response
  --match-code | -mc  Show only responses with matching status codes (e.g., 200,403,500)
  --filter-code | -fc Hide responses with matching status codes (e.g., 401,404)
```
