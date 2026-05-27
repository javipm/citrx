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
- paneles de incidencias con tres pestañas
- tabla completa del access log indexado

El área de incidencias tiene tres pestañas navegables con `Tab`:

| Pestaña                      | Contenido                                                                      |
| ---------------------------- | ------------------------------------------------------------------------------ |
| **SATURATION** (por defecto) | Bursts de rate, DDoS, crawlers IA, bots abusivos — abuso de tráfico/recursos   |
| **SECURITY**                 | Payloads SQLi/XSS/LFI, recon, bots falsos, scanner UA — intentos de compromiso |
| **OTHER**                    | Incidencias de bajo nivel o ruido filtradas de los paneles principales         |

`Tab` cicla: access log → SATURATION → SECURITY → OTHER → access log.

Las incidencias marcadas con `2XX_HIT` tuvieron al menos una respuesta `2xx`,
lo que significa que el payload o probe recibió una respuesta HTTP exitosa.

Atajos:

```text
Tab              cambia foco entre access log y paneles de incidencias
↑/↓              mueve fila
PgUp/PgDn        navega por páginas
Enter / d        abre incidencia o detalle de request
f o /            filtra filas del access log
s o S            abre menú de ordenación
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
s o S            abre menú de ordenación
a                pregunta a OpenAI sobre esta incidencia/selección
e                exporta contexto actual a JSON
b                vuelve al resumen
q                salir
```

El export de incidencia sólo aparece cuando todos los requests relacionados han
terminado de cargarse, para evitar exportar una muestra parcial hidratada en
background.

### Menú De Ordenación

Pulsa `s` o `S` desde la pantalla principal o de incidencia para abrir un menú
centrado sobre el log. El menú permite elegir el campo y el sentido antes de
lanzar cualquier reindexado costoso.

```text
←/→              cambia entre columnas de campo y dirección
↑/↓              elige campo o dirección
Space            selecciona la columna actual y avanza al siguiente paso
Enter            aplica ordenación y cierra el menú
Esc / Backspace  cancela
```

Los valores seleccionados aparecen resaltados en el menú. Cuando una vista
filtrada/ordenada grande, unos tops o un export JSON se están recalculando, la
TUI muestra un estado de carga para que no parezca bloqueada.

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

Puedes usarlos desde la tabla global, desde las filas de una incidencia y desde
los drill-downs de tops. No distinguen mayúsculas/minúsculas y funcionan como
un pequeño lenguaje de consulta:

- búsqueda de texto en IP, hora, método, path, target, status, bytes, UA y línea raw
- términos seguidos equivalen a `AND`
- `AND`, `OR`, `|`, paréntesis y negación con `!` o `NOT`
- `:` significa contiene para campos de texto; `=` significa coincidencia exacta
- `!=` niega una coincidencia de campo
- `>`, `>=`, `<`, `<=` funcionan en `status`, `bytes` y `line`
- `status:2xx`, `status:3xx`, `status:4xx` y `status:5xx` agrupan familias HTTP
- `*` usa comodines anclados, por ejemplo `ip:66.249.*`
- valores entre comillas permiten espacios o símbolos: `ua:"Googlebot/2.1"`
- los valores URL-encoded del filtro se decodifican antes de comparar

Ejemplos habituales:

```text
method:POST status:200 url:*admin*
(method:POST OR method:PUT) status:2xx
(status:403 | status:404) !ua:*Googlebot*
ip:66.249.* bytes>50000
status:5xx path:/checkout
method!=GET status>=400
param:q
param:q=*select*
param:*=*sleep*
query:*utm_*
url:"/admin/login?q=camper"
raw:"union select"
source:access.log line>=10000 line<20000
```

Campos:

```text
ip, method, status, path, target, url, ua, bytes, param, query, source, line, time, raw
```

Alias útiles:

```text
url -> target
timestamp -> time
userAgent -> ua
st -> status
ln -> line
src -> source
qs -> query
mth -> method
params -> param
```

Los filtros de parámetros tienen dos modos:

```text
param:q              cualquier request con parámetro q
param:q=*select*     parámetro q cuyo valor contiene "select"
param:*=*token*      cualquier valor de parámetro que contiene "token"
```

La búsqueda de texto libre viene bien para cazar rápido:

```text
googlebot checkout
198.51.100.10 wp-admin
```

Esos ejemplos equivalen a exigir que ambas palabras aparezcan en la línea
buscable.

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

Cada incidencia tiene un campo `kind` que determina en qué panel de la TUI aparece:

| Kind         | Panel      | Ejemplos                                                           |
| ------------ | ---------- | ------------------------------------------------------------------ |
| `compromise` | SECURITY   | Payloads SQLi/XSS/LFI, probes de recon, bots falsos, scanner tools |
| `saturation` | SATURATION | Bursts DDoS, crawlers IA, crawlers abusivos, hotspots POST         |
| `noise`      | OTHER      | Patrones de bajo nivel poco accionables de forma inmediata         |

`citrx` emite actualmente estas familias de incidencias.

### Payloads Y Recon

| Prefijo ID              | Categoría           | Kind       | Qué significa                                                                     |
| ----------------------- | ------------------- | ---------- | --------------------------------------------------------------------------------- |
| `sqli:`                 | `sql_injection`     | compromise | indicadores de SQL injection como `union select`, sleep/benchmark, SQL codificado |
| `xss:`                  | `xss`               | compromise | indicadores de ejecución en navegador                                             |
| `lfi_rfi:`              | `path_traversal`    | compromise | traversal, inclusión local/remota, `php://filter`, paths sensibles                |
| `ssrf:`                 | `ssrf`              | compromise | localhost, metadata IPs/hosts, params con URLs internas/callback                  |
| `command_injection:`    | `command_injection` | compromise | metacaracteres shell más indicadores de ejecución                                 |
| `recon_sensitive_file:` | `recon`             | compromise | probes a `.env`, `.git`, backups, dumps e internos                                |
| `rare_method:`          | `http_anomaly`      | noise      | métodos HTTP poco habituales (`CONNECT`, `TRACE`, `OPTIONS`)                      |

Las incidencias de payload se agrupan **por IP atacante**, no por path, de modo
que hay una incidencia por IP independientemente de cuántos paths pruebe. Scoring
según el resultado de las respuestas:

- Cualquier respuesta `2xx` → `SECURITY`, `critical/100` + flag `2XX_HIT`
- Cualquier respuesta `5xx` → `SECURITY`, `critical/90`
- Solo respuestas bloqueadas/redirigidas → `OTHER`; contexto útil, no impacto probado

`recon_sensitive_file` requiere al menos **2 respuestas exitosas** o una **ratio de éxito
del 10%** para evitar alertar sobre scanners de 404 típicos.

### Reglas Agregadas Por Path

| Prefijo ID         | Categoría          | Kind             | Qué significa                                                          |
| ------------------ | ------------------ | ---------------- | ---------------------------------------------------------------------- |
| `abusive_crawl:`   | `abusive_crawling` | saturation/noise | path no entrypoint con presión servida material o crawling distribuido |
| `query_explosion:` | `abusive_crawling` | noise            | un path con muchas variantes de query string                           |
| `post_hotspot:`    | `post_hotspot`     | noise            | endpoint con muchas peticiones POST                                    |

### Rate Y DDoS

| Prefijo ID                  | Categoría | Kind       | Qué significa                                                       |
| --------------------------- | --------- | ---------- | ------------------------------------------------------------------- |
| `ddos_rps_burst_single_ip:` | `ddos`    | saturation | una IP supera el umbral de RPS durante varios segundos consecutivos |
| `ddos_global_rps_spike`     | `ddos`    | saturation | el RPS global supera la línea base durante varios segundos          |
| `http_head_flood:`          | `ddos`    | saturation | una IP manda una proporción alta y un pico alto de HEAD             |
| `ddos_distributed_subnet:`  | `ddos`    | saturation | IPv4 `/24` o IPv6 `/48` supera umbrales de RPS e IPs únicas         |

### Tormentas De Errores HTTP

| Prefijo ID        | Categoría      | Kind       | Qué significa                                                       |
| ----------------- | -------------- | ---------- | ------------------------------------------------------------------- |
| `http_4xx_storm:` | `http_anomaly` | noise      | una IP genera muchas respuestas 4xx en buckets de minuto adyacentes |
| `http_5xx_storm:` | `http_anomaly` | saturation | una IP genera muchas respuestas 5xx en buckets de minuto adyacentes |

### Bots Y Scanners

| Prefijo ID                  | Categoría          | Kind             | Qué significa                                                               |
| --------------------------- | ------------------ | ---------------- | --------------------------------------------------------------------------- |
| `ai_scraper_known:`         | `ai_scraper`       | saturation/noise | crawler IA o user-agent de asistente IA conocido, agrupado por bot          |
| `scanner_ua_known:`         | `scanner`          | compromise       | user-agent de scanner o tooling ofensivo conocido                           |
| `scanner_signature_paths:`  | `scanner`          | compromise       | una IP toca muchos paths fingerprint de scanners                            |
| `single_ip_path_explosion:` | `abusive_crawling` | saturation       | una IP supera **10 paths únicos/minuto** de forma sostenida                 |
| `ua_rotation_same_ip:`      | `http_anomaly`     | noise            | una IP usa muchos user-agents distintos **y** peak RPS ≥ 5                  |
| `fake_bot_googlebot:`       | `fake_bot`         | compromise       | UA declara Googlebot core pero la IP no está en rangos Googlebot publicados |
| `fake_bot_bingbot:`         | `fake_bot`         | compromise       | UA declara bingbot pero la IP no está en rangos Bing publicados             |

Notas de detección:

- `single_ip_path_explosion` requiere **pathsPerMinute ≥ 10**, no solo conteo total.
  Las páginas normales que cargan muchos assets no lo disparan.
- `abusive_crawl` entra en `SATURATION` solo cuando suficientes requests llegan a
  servirse (`2xx`/`5xx` material) y hay pico real de servidos por minuto. Tráfico
  dominado por redirects o 403 queda en `OTHER`.
- `ua_rotation_same_ip` requiere **peak RPS ≥ 5**, pero sigue en `OTHER` salvo que
  otro detector encuentre impacto de payload. NAT compartido (p.ej. oficinas AWS)
  genera muchos user-agents a baja tasa sin ser malicioso.
- `fake_bot_*` requiere **al menos 10 requests** de esa IP.
- Las IPs confirmadas como Googlebot o Bingbot legítimo (verificadas contra rangos
  publicados) quedan excluidas de todas las detecciones de bots y scanners.
- `ai_scraper_known` es `SATURATION` solo con fan-out brusco de paths; volumen
  total alto repartido durante días queda en `OTHER`.

Los snapshots de rangos Googlebot/Bingbot están en el código. Se refrescan con:

```bash
pnpm run update-bot-ranges
```

## Scoring

Cada incidencia tiene:

- `kind`: `compromise`, `saturation` o `noise` (determina el panel en la TUI)
- `severity`: `info`, `low`, `medium`, `high`, `critical`
- `score`: `0` a `100`
- `evidence`: key/value tipado para auditoría
- `samples`: ejemplos redactados cuando aplica
- `successful?`: `true` cuando al menos una respuesta fue `2xx`

Umbrales de severidad:

| Rango de score | Severidad  |
| -------------- | ---------- |
| 0–24           | `info`     |
| 25–49          | `low`      |
| 50–74          | `medium`   |
| 75–89          | `high`     |
| 90–100         | `critical` |

Multiplicadores post-proceso aplicados tras el scoring base:

- `+10` si la misma `evidence.ip` aparece en dos o más incidencias (atacante correlado)
- `+15` si el patrón persiste durante al menos 30 minutos (bonus de persistencia)
- `-10` para crawlers IA moderados que pidieron `robots.txt`

Notas:

- El bonus de persistencia **no aplica** a `ai_scraper_known:*` — los crawlers IA
  funcionan durante semanas de forma natural, así que la duración sola no es señal.
- Las incidencias se ordenan dentro de cada panel por peso de `kind` primero
  (compromise → saturation → noise), luego por score descendente.
- El score final se limita a `[0, 100]` y después se recalcula la severidad.

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
