# citrx

`citrx` es una CLI/TUI local-first para analizar access logs de Apache y Nginx.

Procesa logs grandes en streaming, valida que las entradas parezcan access logs,
detecta incidencias de seguridad y abuso en local, abre una interfaz interactiva
en terminal por defecto y puede preguntar a OpenAI, solo cuando tú lo pides,
sobre la vista actual o sobre las filas seleccionadas.

> Documentación en inglés: [README.md](./README.md)

## Para qué sirve

En los access logs suele haber crawlers caros, ruido de scanners, bots falsos,
payloads SQLi/XSS, abuso de POST y picos de tráfico. `citrx` está pensado para
DevOps, equipos de seguridad y backend developers que necesitan responder
rápido:

- ¿Qué ha pasado?
- ¿Qué rutas, IPs, métodos, user-agents y query params están implicados?
- ¿Qué requests tengo que revisar?
- ¿Qué regla WAF o rate-limit puede reducir el impacto?

El flujo normal es:

1. Ejecutar análisis local determinista.
2. Explorar incidencias y requests relacionados en la TUI.
3. Filtrar, ordenar, inspeccionar y seleccionar filas.
4. Preguntar a OpenAI solo si quieres ayuda interpretando ese contexto.

## Requisitos

- Node.js `>=24.15`
- pnpm `>=11` para desarrollo

Cuando el paquete se publique, la idea es poder usarlo con `npx citrx`.

## Instalación Y Uso

Desde el repo:

```bash
pnpm install
pnpm run dev -- /ruta/al/access.log
```

Después de compilar:

```bash
pnpm run build
node dist/cli.js /ruta/al/access.log
```

Ejemplos habituales:

```bash
# Abre la TUI interactiva por defecto
citrx /var/log/nginx/access.log

# Analiza varios paths, carpetas y ficheros comprimidos
citrx ./logs access.log.gz archive.zip

# Lee desde stdin
cat access.log | citrx -

# Reporte por terminal sin TUI
citrx access.log --no-interactive

# Reportes JSON / Markdown / HTML
citrx access.log --json
citrx access.log --markdown --out report.md
citrx access.log --html --out report.html

# Rango de fechas
citrx access.log --since 2026-05-25T00:00:00Z --until 2026-05-25T23:59:59Z

# Parser explícito
citrx access.log --format apache_combined
```

El subcomando `citrx analyze` se eliminó. Usa:

```bash
citrx <paths...>
```

## Opciones CLI

```text
Uso: citrx [options] <paths...>

Opciones:
  --json                    Escribe salida JSON para automatización
  --markdown                Escribe salida Markdown
  --html                    Escribe un reporte HTML autocontenido
  --out <path>              Escribe el reporte a un fichero
  --no-interactive          Imprime reporte terminal en vez de abrir la TUI
  --format <format>         auto, apache_common, apache_combined,
                            nginx_combined o custom:<name>
  --format-config <path>    JSON con formatos custom de access log
  --top <n>                 Limita los listados top
  --since <date>            Incluye entradas desde esta fecha
  --until <date>            Incluye entradas hasta esta fecha
  --include <glob>          Incluye paths que coincidan con el glob
  --exclude <glob>          Excluye paths que coincidan con el glob
  --no-color                Desactiva colores en terminal
  --debug                   Muestra detalles de error
  -v, --version             Muestra la versión
```

`NO_COLOR=1` desactiva colores. `CITRX_QUIET=1` desactiva banner/progreso en
salida por terminal.

Opciones eliminadas: `--geo`, `--no-session`, `--incident-lines`.

## Entradas

Entradas soportadas:

- ficheros de access log individuales
- carpetas
- stdin con `-`
- `.gz`
- `.br`
- `.zip`
- `.tar.gz`
- `.tgz`

ZIP y TAR se inspeccionan buscando candidatos como `access.log`, `.log`, `.txt`,
logs sin extensión, `.gz` y `.br`.

`citrx` procesa en streaming y no carga el log completo en memoria. Para la TUI
crea un índice temporal del access log en la carpeta temporal del sistema. Ese
workspace se elimina al salir del proceso.

## Formatos De Access Log

Formatos integrados:

- `apache_common`
- `apache_combined`
- `nginx_combined`

Por defecto usa `--format auto`. `citrx` toma una muestra de cada entrada,
elige el mejor parser y falla pronto si la muestra no parece un access log de
Apache/Nginx.

Los formatos custom se configuran con `--format custom:<name>` y
`--format-config <path>`:

```json
{
  "formats": [
    {
      "name": "pipe",
      "pattern": "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})\\|(?<bytes>\\S+)\\|(?<userAgent>.*)$",
      "fields": {
        "ip": "ip",
        "timestamp": "timestamp",
        "method": "method",
        "target": "target",
        "protocol": "protocol",
        "status": "status",
        "bytes": "bytes",
        "userAgent": "userAgent"
      }
    }
  ]
}
```

## TUI Interactiva

Si stdin/stdout son TTY y no pides un formato de reporte, `citrx` abre una UI
a pantalla completa en terminal.

### Pantalla Principal

Muestra:

- resumen del análisis
- lista navegable de incidencias
- tabla completa del access log indexado

Atajos:

```text
Tab              cambia foco entre access log e incidencias
↑/↓              mueve fila
PgUp/PgDn        navega por páginas
Enter / d        abre incidencia o detalle de request
f o /            filtra filas del access log
s                cambia columna de ordenación
S                cambia dirección de ordenación
t                abre tops globales
Space            selecciona fila actual
A                selecciona filas visibles
a                pregunta a OpenAI sobre vista/selección
e                exporta contexto actual a JSON
q                salir
```

### Pantalla De Incidencia

Muestra evidencia de la incidencia y todos los requests relacionados.

Los atajos son deliberadamente parecidos a la pantalla principal:

```text
↑/↓              mueve fila
PgUp/PgDn        navega por páginas
Enter / d        abre detalle de request
t                abre tops de esta incidencia
Space            selecciona fila actual
A                selecciona filas visibles
f o /            filtra filas
s                cambia columna de ordenación
S                cambia dirección de ordenación
a                pregunta a OpenAI sobre esta incidencia/selección
e                exporta contexto actual a JSON
b                vuelve al resumen
q                salir
```

### Pantalla De Tops

Disponible desde resumen o incidencia con `t`.

Paneles:

- top IPs
- top paths
- top user-agents
- top query params
- top query param + valor

Atajos:

```text
Tab              cambia panel
↑/↓              mueve dentro del panel
Enter            aplica filtro usando el valor seleccionado
a                pregunta a OpenAI sobre los tops visibles
t / b / Esc      volver
q                salir
```

Si hay un filtro activo, los tops se calculan sobre el subconjunto filtrado.

### Detalle De Request

Se abre con `Enter` o `d` sobre una fila del log. Muestra source, timestamp, IP,
método, status, bytes, path, target, user-agent y línea raw con wrapping.

```text
↑/↓ PgUp/PgDn    scroll
d / b / Esc      cerrar
q                salir
```

## Filtros

Los filtros funcionan sobre el access log global y sobre las filas relacionadas
con una incidencia.

Soportan:

- búsqueda de texto
- campos concretos
- `AND` por defecto
- `OR` o `|`
- grupos con paréntesis
- negación con `!`
- comodín `*`
- comparaciones numéricas para `status`, `bytes` y `line`

Ejemplos:

```text
method:POST status:200 url:*admin*
(method:POST OR method:PUT) status:2xx
(status:403 | status:404) !ua:*Googlebot*
ip:66.249.* bytes>50000
param:q
param:q=*select*
url:"/admin/login?q=camper"
```

Campos:

```text
ip, method, status, path, url, target, ua, bytes, param, source, line, time, raw
```

## Modo OpenAI

OpenAI nunca se llama durante el análisis inicial. Solo se llama cuando pulsas
`a` en la TUI.

Configuración:

```bash
export OPENAI_API_KEY="sk-proj-..."
```

Opcionales:

```bash
export CITRX_OPENAI_MODEL="gpt-5.4-mini"
export CITRX_AI_MAX_LINES="200"
export CITRX_AI_MAX_CHARS="60000"
```

OpenAI recibe contexto compacto y redactado:

- resumen del reporte
- estadísticas temporales
- top IPs/paths/métodos/statuses
- estadísticas de comportamiento
- evidencia de la incidencia seleccionada
- filas seleccionadas, o filas visibles filtradas si no hay selección
- referencias a user-agents para no repetir cadenas largas

La respuesta aparece en una pantalla dedicada con scroll y renderizado Markdown
ligero.

Importante: los access logs no contienen ASN. Si ASN/organización no está en el
contexto local, el modelo tiene instrucción explícita de no inventarlo.

## Reportes

Salidas soportadas:

- reporte terminal con colores
- JSON (`--json`)
- Markdown (`--markdown`)
- HTML offline autocontenido (`--html`)

Usa `--out <path>` para escribir Markdown/HTML/JSON a disco.

Reportes HTML:

- CSS/JS autocontenido
- sin recursos externos
- salida escapada
- tablas ordenables/filtrables
- preparado para imprimir/PDF

## Tipos De Incidencias

`citrx` emite actualmente estas familias de incidencias.

### Payloads Y Recon

| Prefijo ID | Categoría | Qué significa |
|---|---|---|
| `sqli:` | `sql_injection` | indicadores de SQL injection como `union select`, sleep/benchmark, SQL codificado, prepared statements |
| `xss:` | `xss` | indicadores de ejecución en navegador |
| `lfi_rfi:` | `path_traversal` | traversal, inclusión local/remota, `php://filter`, paths sensibles |
| `ssrf:` | `ssrf` | localhost, metadata IPs/hosts, params con URLs internas/callback |
| `command_injection:` | `command_injection` | metacaracteres shell más indicadores de ejecución |
| `recon_sensitive_file:` | `recon` | probes a `.env`, `.git`, backups, dumps e internos |
| `rare_method:` | `http_anomaly` | métodos HTTP poco habituales en tráfico público |

Las incidencias de payload se agrupan por regla y path. Si todas las respuestas
son 404/4xx, el score baja para que los probes muertos no parezcan tan urgentes
como payloads que devuelven éxito.

### Reglas Agregadas Por Path

| Prefijo ID | Categoría | Qué significa |
|---|---|---|
| `abusive_crawl:` | `abusive_crawling` | path no entrypoint con alto volumen repetido por muchos clientes |
| `query_explosion:` | `abusive_crawling` | un path con muchas variantes de query string |
| `post_hotspot:` | `post_hotspot` | endpoint con muchas peticiones POST |

### Rate Y DDoS

| Prefijo ID | Categoría | Qué significa |
|---|---|---|
| `ddos_rps_burst_single_ip:` | `ddos` | una IP supera el umbral de RPS durante varios segundos consecutivos |
| `ddos_global_rps_spike` | `ddos` | el RPS global supera la línea base durante varios segundos |
| `http_head_flood:` | `ddos` | una IP manda una proporción alta y un pico alto de HEAD |
| `ddos_distributed_subnet:` | `ddos` | IPv4 `/24` o IPv6 `/48` supera umbrales de RPS e IPs únicas |

### Tormentas De Errores HTTP

| Prefijo ID | Categoría | Qué significa |
|---|---|---|
| `http_4xx_storm:` | `http_anomaly` | una IP genera muchas respuestas 4xx en buckets de minuto adyacentes |
| `http_5xx_storm:` | `http_anomaly` | una IP genera muchas respuestas 5xx en buckets de minuto adyacentes |

### Bots Y Scanners

| Prefijo ID | Categoría | Qué significa |
|---|---|---|
| `ai_scraper_known:` | `ai_scraper` | crawler IA o user-agent de asistente IA conocido, agrupado por bot |
| `scanner_ua_known:` | `scanner` | user-agent de scanner o tooling ofensivo conocido |
| `scanner_signature_paths:` | `scanner` | una IP toca muchos paths fingerprint de scanners |
| `single_ip_path_explosion:` | `abusive_crawling` | una IP toca cientos de paths únicos |
| `ua_rotation_same_ip:` | `http_anomaly` | una IP usa muchos user-agents distintos |
| `fake_bot_googlebot:` | `fake_bot` | UA declara Googlebot core pero la IP no está en rangos Googlebot publicados |
| `fake_bot_bingbot:` | `fake_bot` | UA declara bingbot pero la IP no está en rangos Bing publicados |

Los snapshots de rangos Googlebot/Bingbot están en el código. Se refrescan con:

```bash
pnpm run update-bot-ranges
```

## Scoring

Cada incidencia tiene:

- `severity`: `info`, `low`, `medium`, `high`, `critical`
- `score`: `0` a `100`
- `evidence`: key/value tipado para auditoría
- `samples`: ejemplos redactados cuando aplica

El scoring aplica multiplicadores post-proceso:

- `+10` si la misma `evidence.ip` aparece en dos o más incidencias
- `+15` si el patrón persiste durante al menos 30 minutos
- `-10` para crawlers IA moderados que pidieron `robots.txt`

El score final se limita a `[0, 100]` y después se recalcula la severidad.

## Seguridad Y Privacidad

- Análisis local primero.
- Sin telemetría.
- OpenAI solo con acción explícita `a`.
- Secrets en URLs/query values se redactan.
- HTML escapado.
- El contenido del log nunca se ejecuta.
- Los índices temporales de la TUI se borran al salir.

Claves redactadas en query string:

```text
token, _token, sid, session, password, passwd, key, secret, jwt, auth, authorization
```

## Desarrollo

```bash
pnpm install
pnpm run typecheck
pnpm test
pnpm run build
```

Ejecutar desde código fuente:

```bash
pnpm run dev -- examples/access_ssl_log
pnpm run dev -- examples/access_ssl_log --json
```

Actualizar snapshots de rangos bot:

```bash
pnpm run update-bot-ranges
```

## Estado Del Proyecto

`citrx` es pre-1.0 y todavía no está publicado. La CLI y las formas de reporte
pueden cambiar mientras se afina el flujo principal.

## Licencia

MIT
