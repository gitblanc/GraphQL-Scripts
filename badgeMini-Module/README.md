# Mini-módulo: detección de SQLi para GraphQL (badgeMini-Module) - Python

Este módulo detecta indicios de SQL Injection en endpoints GraphQL mediante:
- introspección del esquema para localizar queries con argumentos,
- envío de payloads de prueba a argumentos de tipo String/ID,
- análisis de respuestas para detectar errores SQL, cambios en datos o resultados nulos.

Requisitos
- Python 3.9+
- Instalar dependencias: pip install -r requirements.txt

Instalación
1. Copiar la carpeta `badgeMini-Module` dentro de tu repo.
2. Desde la carpeta ejecutar:
   pip install -r badgeMini-Module/requirements.txt

Uso
- Ejecución básica:
  python badgeMini-Module/sqli_detector.py <ENDPOINT> '[{"Header-Name":"value","Another":"v"}]'

  Ejemplo:
  python badgeMini-Module/sqli_detector.py http://localhost:4000/graphql '{"Authorization":"Bearer TOKEN"}'

- Opciones:
  --json-out <file>  Guarda los hallazgos en JSON.

Consideraciones éticas y legales
- Nunca escanear sistemas sin autorización.
- Usa este módulo únicamente en entornos de prueba o con permiso explícito del propietario.

Qué hace y qué no
- Detecta indicios (errores SQL, cambios en respuesta, respuestas nulas) — no realiza explotación automatizada o exfiltración.
- Se puede extender para time-based, blind-SQLi o payloads por DBMS.

Extensiones sugeridas
- Detección por time-based (sleep) para blind-SQLi.
- Más payloads por motor (MySQL / Postgres / SQLite / MSSQL).
- Integración con autenticación OAuth/bearer dinámico o con reintentos.
