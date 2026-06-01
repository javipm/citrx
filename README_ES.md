<div align="center">

# 🍋 citrx

### Análisis local de logs de acceso Apache y Nginx, en tu terminal

Procesa logs enormes en streaming, detecta ataques y abuso con reglas locales
deterministas, explóralo todo en una TUI interactiva — y consulta a la IA solo
cuando **tú** lo decides.

[![npm](https://img.shields.io/npm/v/@javipm/citrx?color=cb3837&logo=npm)](https://www.npmjs.com/package/@javipm/citrx)
[![node](https://img.shields.io/badge/node-%3E%3D22-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![types](https://img.shields.io/badge/types-TypeScript-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![privacy](https://img.shields.io/badge/privacidad-local--first-success)](#-seguridad-y-privacidad)

[English](./README.md) · **Español**

</div>

---

```bash
# Un fichero, una carpeta, comprimido o plano — citrx lo detecta solo
npx @javipm/citrx /var/log/nginx/access.log
npx @javipm/citrx /var/log/nginx/          # una carpeta entera de logs
npx @javipm/citrx access.log.gz logs.zip   # .gz .br .zip .tar.gz .tgz
cat access.log | npx @javipm/citrx -        # stdin
```

Ese comando procesa la entrada en streaming, la valida, ejecuta ~30 reglas de
detección y abre una TUI a pantalla completa. Sin cuenta, sin subir nada, sin
telemetría.

<div align="center">

<!-- Coloca una captura real en assets/tui-summary.webp — ver assets/README.md -->
<img src="./assets/tui-summary.webp" alt="TUI de citrx — pantalla de resumen con pestañas de incidentes y la tabla global de logs" width="860">

</div>

---

## 🖼️ Capturas

<div align="center">

<table>
  <tr>
    <td width="50%"><img src="./assets/tui-summary.webp" alt="Pantalla de resumen — pestañas de incidentes + tabla global"><br><sub><b>Resumen</b> — pestañas de incidentes + tabla de logs indexada</sub></td>
    <td width="50%"><img src="./assets/tui-incident.webp" alt="Pantalla de incidente — evidencia + filas relacionadas"><br><sub><b>Incidente</b> — evidencia + filas de log relacionadas</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="./assets/tui-top-values.webp" alt="Pantalla de top values"><br><sub><b>Top values</b> — top de IPs, rutas, UAs, parámetros</sub></td>
    <td width="50%"><img src="./assets/tui-filter.webp" alt="Barra de filtro con una expresión de consulta"><br><sub><b>Filtro</b> — lenguaje de consulta sobre el log</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="./assets/report-terminal.webp" alt="Informe de terminal"><br><sub><b>Informe de terminal</b> — <code>--no-interactive</code></sub></td>
    <td width="50%"><img src="./assets/report-html.webp" alt="Informe HTML autocontenido"><br><sub><b>Informe HTML</b> — autocontenido, offline</sub></td>
  </tr>
</table>

</div>

---

## 📑 Índice

- [Por qué citrx](#-por-qué-citrx)
- [Características](#-características)
- [Inicio rápido](#-inicio-rápido)
- [Qué aspecto tiene la salida](#-qué-aspecto-tiene-la-salida)
- [Referencia de CLI](#-referencia-de-cli)
- [Entradas y formatos](#-entradas-y-formatos)
- [TUI interactiva](#-tui-interactiva)
- [Filtrado](#-filtrado)
- [Modo IA (opt-in)](#-modo-ia-opt-in)
- [Informes](#-informes)
- [Reglas de detección](#-reglas-de-detección)
- [Puntuación](#-puntuación)
- [Seguridad y privacidad](#-seguridad-y-privacidad)
- [Desarrollo](#-desarrollo)
- [Licencia](#-licencia)

---

## 🤔 Por qué citrx

Los logs de acceso esconden crawlers caros, ruido de escáneres, bots falsos,
payloads SQLi/XSS, abuso de POST y picos de tráfico. `citrx` está pensado para
DevOps, ingenieros de seguridad y desarrolladores backend que necesitan
respuestas rápidas a:

- **¿Qué ha pasado?**
- **¿Qué rutas, IPs, métodos, user-agents y parámetros están implicados?**
- **¿Qué peticiones debo inspeccionar de verdad?**
- **¿Qué regla de WAF o rate-limit reduciría el impacto?**

El flujo es deliberadamente offline-first:

```
1. Análisis local determinista       →  sin red, memoria acotada
2. Explorar incidentes + peticiones   →  TUI interactiva
3. Filtrar, ordenar, inspeccionar     →  pequeño lenguaje de consulta
4. Preguntar a la IA — solo con `a`    →  contexto compacto y redactado
```

---

## ✨ Características

| | |
| --- | --- |
| 🌊 **Streaming** | Parsing línea a línea con memoria acotada. Logs de varios GB no se cargan enteros en RAM. |
| 🧭 **Autodetección de formato** | Muestrea cada entrada, elige `apache_common` / `apache_combined` / `nginx_combined` y falla pronto si no es un log de acceso. |
| 🧩 **Formatos personalizados** | Config JSON declarativa con un regex + campos nombrados, validada con `zod`. |
| 🛡️ **~30 reglas de detección** | SQLi/XSS/LFI/SSRF/inyección de comandos, recon, bots falsos, escáneres, ráfagas DDoS, crawlers de IA, hotspots de POST, tormentas de errores. |
| 🖥️ **TUI completa** | Pestañas de incidentes, tabla de logs indexada, carga de filas bajo demanda, top values, detalle de petición, exportaciones. |
| 🔎 **Lenguaje de consulta** | `AND`/`OR`/`NOT`, paréntesis, operadores de campo, familias de estado, comodines, filtros por parámetro. |
| 📤 **Informes** | Terminal, JSON, Markdown y HTML offline autocontenido. |
| 🤖 **IA opt-in** | OpenAI nunca se llama durante el análisis — solo al pulsar `a`, con contexto redactado. |
| 📦 **Entradas comprimidas** | `.gz`, `.br`, `.zip`, `.tar.gz`, `.tgz`, carpetas y stdin. |
| 🔒 **Local-first** | Sin telemetría, secretos redactados, índice temporal borrado al salir. |

---

## 🚀 Inicio rápido

### Ejecutar sin instalar

```bash
# npm
npx @javipm/citrx /var/log/nginx/access.log

# pnpm
pnpx @javipm/citrx /var/log/nginx/access.log

# yarn
yarn dlx @javipm/citrx /var/log/nginx/access.log

# bun
bunx @javipm/citrx /var/log/nginx/access.log
```

### Instalación global

```bash
npm i -g @javipm/citrx
citrx /var/log/nginx/access.log
```

### Invocaciones habituales

```bash
# Analizar varias rutas, carpetas y ficheros comprimidos a la vez
citrx ./logs access.log.gz archive.zip

# Leer desde stdin
cat access.log | citrx -

# Informe de terminal no interactivo (CI, pipes, cron)
citrx access.log --no-interactive

# Informes estructurados
citrx access.log --json
citrx access.log --markdown --out report.md
citrx access.log --html     --out report.html

# Restringir un rango de fechas
citrx access.log --since 2026-05-25T00:00:00Z --until 2026-05-25T23:59:59Z

# Forzar un parser
citrx access.log --format apache_combined
```

> **Requisitos:** Node.js `>=22` (desarrollado y probado en `24.15`). `npx`/`pnpx`
> se encargan del resto.

Los **códigos de salida** hacen que `citrx` se integre bien en CI:

| Código | Significado |
| ------ | ----------- |
| `0`    | Éxito, sin incidentes high/critical |
| `1`    | Error de ejecución / configuración |
| `2`    | Se encontraron incidentes high o critical |

---

## 📟 Qué aspecto tiene la salida

Informe no interactivo sobre un log sintético pequeño
(`citrx demo_access.log --no-interactive`):

```text
citrx access log analysis

Files: 1
Lines: 72/72
Invalid: 0
Bytes served: 86972
Time range: 2026-05-25T10:00:01.000Z to 2026-05-25T10:05:59.000Z
Peak global RPS: 3 at 2026-05-25T10:03:00.000Z
Formats: apache_combined

Top IPs
      60  8.8.4.4
       4  198.51.100.23
       3  45.83.66.12
       2  192.0.2.55
...

Known AI bots
       3  GPTBot ips=1 paths=1 robots=no

Security incidents (attacks)
  critical 100  SQL injection payload count=1
       ip: 198.51.100.23
       /index.php
       sample: /index.php?id=1+AND+SLEEP(5)
  critical  95  Known scanner user-agent count=4
       ip: 198.51.100.23
  critical  90  Sensitive file probe count=2 2XX_HIT
       ip: 198.51.100.23
       /.env
       /.git/config
  high      85  Known scanner user-agent count=2
       ip: 192.0.2.55
```

> `2XX_HIT` significa que el payload o sondeo recibió al menos una respuesta
> `2xx` — una respuesta *posiblemente* válida que conviene inspeccionar, no una
> prueba de compromiso.

---

## 🧰 Referencia de CLI

```text
Usage: citrx [options] <paths...>

Options:
  --json                  Write machine-readable JSON output.
  --markdown              Write Markdown output.
  --html                  Write a self-contained HTML report.
  --out <path>            Write report output to a file.
  --no-interactive        Print the terminal report instead of opening the TUI.
  --format <format>       auto, apache_common, apache_combined,
                          nginx_combined, or custom:<name>.   (default: auto)
  --format-config <path>  JSON file with custom access-log formats.
  --top <n>               Limit top lists.                    (default: 20)
  --since <date>          Include entries at or after this date.
  --until <date>          Include entries at or before this date.
  --include <glob>        Include paths matching this glob.
  --exclude <glob>        Exclude paths matching this glob.
  --no-color              Disable colored terminal output.
  --debug                 Print debug details on failure.
  -v, --version           Display the current version.
  -h, --help              Display help for command.
```

Entorno:

- `NO_COLOR=1` — desactiva el color.
- `CITRX_QUIET=1` — silencia el ruido de arranque/progreso en salida de terminal.

Si stdout/stdin son TTY y no se pide ningún formato de informe, `citrx` abre la
TUI por defecto. `--no-interactive` imprime el informe de terminal.

---

## 📥 Entradas y formatos

### Entradas soportadas

Ficheros sueltos · carpetas · stdin (`-`) · `.gz` · `.br` · `.zip` · `.tar.gz` · `.tgz`

Los archivos ZIP/TAR se escanean en busca de logs candidatos (`access.log`,
`.log`, `.txt`, logs sin extensión, `.gz`, `.br`). Todo se procesa en streaming
— los logs nunca se cargan enteros en memoria. La TUI construye un índice
**temporal** bajo el directorio temporal del SO y lo elimina al salir.

### Formatos integrados

`apache_common` · `apache_combined` · `nginx_combined`

Por defecto `--format auto`: `citrx` muestrea cada entrada, elige el mejor parser
y falla pronto cuando la muestra no parece un log de acceso Apache/Nginx.

### Formatos personalizados

Una config JSON declarativa, un regex con grupos nombrados, validada por `zod`:

```json
{
  "formats": [
    {
      "name": "pipe",
      "pattern": "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})\\|(?<bytes>\\S+)\\|(?<userAgent>.*)$",
      "fields": {
        "ip": "ip", "timestamp": "timestamp", "method": "method",
        "target": "target", "protocol": "protocol", "status": "status",
        "bytes": "bytes", "userAgent": "userAgent"
      }
    }
  ]
}
```

```bash
citrx access.log --format custom:pipe --format-config ./formats.json
```

Campos obligatorios: `ip`, `timestamp`, `method`, `target`, `protocol`, `status`.
Opcionales: `bytes`, `referer`, `userAgent`, `host`, `requestTime`,
`upstreamTime`, `forwardedFor`.

---

## 🖥️ TUI interactiva

Cuando stdout/stdin son TTY y no se pide informe, `citrx` abre una interfaz de
terminal a pantalla completa. Es la superficie principal del producto, no una
vista de depuración.

```
┌─ citrx ────────────────────────────────────────────────────────────────────┐
│  [ access log ] [ SATURATION ] [ SECURITY ] [ OTHER ]          Tab to switch │
├──────────────────────────────────────────────────────────────────────────────┤
│  #     IP              TIME      MTH  ST   BYTES  PATH                        │
│  3     198.51.100.23   10:01:11  GET  500      0  /index.php?id=1+AND+SLEEP.. │
│  5     198.51.100.23   10:01:12  GET  200   1200  /.env                       │
│  7     192.0.2.55      10:02:00  GET  404      0  /wp-admin/                  │
│ ...                                                                           │
├──────────────────────────────────────────────────────────────────────────────┤
│  f filtrar  s ordenar  t top   Enter detalle  a IA   e exportar  h ayuda     │
└──────────────────────────────────────────────────────────────────────────────┘
```

<div align="center">

<!-- assets/tui-incident.webp -->
<img src="./assets/tui-incident.webp" alt="Pantalla de incidente de citrx" width="820">

</div>

### Pantalla de resumen

El área de incidentes tiene tres pestañas (ciclo con `Tab`: access log →
SATURATION → SECURITY → OTHER → access log):

| Pestaña | Contenido |
| --- | --- |
| 🌊 **SATURATION** (por defecto) | Ráfagas de tráfico, DDoS, crawlers de IA, bots abusivos — abuso de tráfico/recursos |
| 🛡️ **SECURITY** | Payloads SQLi/XSS/LFI, recon, bots falsos, UAs de escáner — intentos de compromiso |
| 🗂️ **OTHER** | Incidentes de baja señal / ruido filtrados de los paneles principales |

```text
Tab              cambiar foco entre el log y los paneles de incidentes
↑/↓              mover fila         PgUp/PgDn   paginar filas
Enter / d        abrir incidente o detalle de petición
f o /            filtrar filas del log
s o S            menú de orden      t           top values global
Space            seleccionar fila   A           seleccionar filas visibles
a                preguntar a la IA sobre la vista/selección
e                menú de exportación (CSV, JSON, TSV)
r                reiniciar filtro, orden y selección de filas
h                overlay de ayuda contextual (teclas + sintaxis de filtros)
q                preguntar antes de salir
```

### Pantalla de incidente

Evidencia + todas las líneas de log relacionadas. Las filas se cargan bajo
demanda en buckets de tamaño fijo, así que incluso incidentes enormes responden
al instante. Filtrar u ordenar un incidente grande muestra progreso en segundo
plano en la barra de estado — pulsa `Esc` para cancelar y revertir.

```text
↑/↓ · PgUp/PgDn  navegar            Enter / d   abrir detalle de petición
t                top values del incidente (sobre el conjunto completo de filas)
f · s/S          filtrar · ordenar  Space · A   seleccionar fila · página visible
a · e            preguntar IA · exportar        r   reiniciar filtro + selección
b                volver al resumen
```

### Top values · detalle de petición · exportación

- **Top values** (`t`): top de IPs, rutas, user-agents, parámetros y valores de
  parámetro. Respeta el filtro activo. `Enter` aplica un filtro desde un valor.
- **Detalle de petición** (`Enter`/`d`): fuente, timestamp, IP, método, estado,
  bytes, ruta, target, user-agent y línea cruda con ajuste de texto.
- **Exportación** (`e`): CSV / JSON / TSV. El resumen exporta las filas
  seleccionadas o el resultado filtrado completo; el incidente exporta en
  streaming todas las filas filtradas a un fichero temporal y lo renombra de
  forma atómica al terminar. `Esc` aborta una exportación en curso.

> Las operaciones largas de filtrado/orden/top/exportación siempre muestran un
> estado de carga — la app nunca *parece* congelada — y `Esc` cancela
> consistentemente la operación activa antes de navegar.

---

## 🔎 Filtrado

Los filtros funcionan sobre el log global, las filas de incidente y los
drill-downs de top values. Insensibles a mayúsculas, con un pequeño lenguaje de
consulta:

- texto plano busca en IP, hora, método, ruta, target, estado, bytes, UA, línea cruda
- términos adyacentes significan `AND`; explícitos `AND`, `OR`, `|`, paréntesis y `!`/`NOT`
- `:` = contiene, `=` = exacto, `!=` = coincidencia negada
- `>`, `>=`, `<`, `<=` para `status`, `bytes`, `line`
- familias de estado: `status:2xx`, `status:3xx`, `status:4xx`, `status:5xx`
- comodines anclados: `ip:66.249.*`
- valores entrecomillados para espacios/símbolos: `ua:"Googlebot/2.1"`
- los valores URL-encoded se decodifican antes de comparar

```text
method:POST status:200 url:*admin*
(method:POST OR method:PUT) status:2xx
(status:403 | status:404) !ua:*Googlebot*
ip:66.249.* bytes>50000
status:5xx path:/checkout
method!=GET status>=400
param:q                # cualquier petición con parámetro q
param:q=*select*       # valor de q contiene "select"
param:*=*sleep*        # cualquier valor de parámetro contiene "sleep"
raw:"union select"
source:access.log line>=10000 line<20000
```

**Campos:** `ip, method, status, path, target, url, ua, bytes, param, query, source, line, time, raw`

**Alias:** `url→target`, `timestamp→time`, `userAgent→ua`, `st→status`,
`ln→line`, `src→source`, `qs→query`, `mth→method`, `params→param`

El texto suelto va genial para cazar rápido — `googlebot checkout` exige ambas
palabras en algún punto de la línea buscable.

---

## 🤖 Modo IA (opt-in)

OpenAI **nunca** se llama durante el análisis — solo al pulsar `a` en la TUI con
`OPENAI_API_KEY` definida.

```bash
export OPENAI_API_KEY="sk-proj-..."

# opcional
export CITRX_OPENAI_MODEL="gpt-5.4-mini"
export CITRX_AI_MAX_LINES="200"
export CITRX_AI_MAX_CHARS="60000"
```

Recibe **solo** contexto compacto y redactado:

- resumen del informe + estadísticas de tiempo
- top de IPs / rutas / métodos / estados + estadísticas de comportamiento
- evidencia del incidente seleccionado
- filas seleccionadas, o filas filtradas visibles si no hay selección
- referencias a user-agents en vez de repetir UAs largos

La respuesta se renderiza en una pantalla scrollable dedicada con Markdown
ligero. Los logs de acceso no contienen datos de ASN, así que se instruye al
modelo para que nunca invente ASN/organización.

---

## 📊 Informes

| Formato | Flag | Notas |
| --- | --- | --- |
| Terminal | `--no-interactive` (o sin TTY) | Resumen + incidentes con color |
| JSON | `--json` | Legible por máquina, modelo de informe tipado |
| Markdown | `--markdown` | Ideal para tickets / PRs |
| HTML | `--html` | **Autocontenido, offline, sin recursos externos** |

Usa `--out <path>` para escribir a disco. Los informes HTML incrustan CSS/JS,
escapan todos los datos, traen tablas ordenables/filtrables y son aptos para
impresión/PDF.

---

## 🛡️ Reglas de detección

Cada incidente lleva un `kind` que determina su panel en la TUI:

| Kind | Panel | Ejemplos |
| --- | --- | --- |
| `compromise` | 🛡️ SECURITY | Payloads SQLi/XSS/LFI, recon, bots falsos, herramientas de escaneo |
| `saturation` | 🌊 SATURATION | Ráfagas DDoS, crawlers de IA, crawlers abusivos, hotspots de POST |
| `noise` | 🗂️ OTHER | Patrones de baja señal que difícilmente necesitan acción inmediata |

<details>
<summary><strong>Reglas de payload y recon</strong></summary>

| Prefijo ID | Categoría | Kind | Significado |
| --- | --- | --- | --- |
| `sqli:` | `sql_injection` | compromise | `union select`, sleep/benchmark, SQL codificado |
| `xss:` | `xss` | compromise | indicadores de ejecución de script/navegador |
| `lfi_rfi:` | `path_traversal` | compromise | traversal, LFI/RFI, `php://filter`, rutas sensibles |
| `ssrf:` | `ssrf` | compromise | localhost, IPs/hosts de metadata, params tipo callback |
| `command_injection:` | `command_injection` | compromise | metacaracteres de shell + indicadores de comando |
| `recon_sensitive_file:` | `recon` | compromise | sondeos de `.env`, `.git`, backups, dumps |
| `rare_method:` | `http_anomaly` | noise | métodos poco comunes (`CONNECT`, `TRACE`, `OPTIONS`) |

Los incidentes de payload se agrupan **por IP atacante** (un incidente por IP).
Puntuación por resultado de respuesta:

- cualquier `2xx` → SECURITY, `critical/100` + `2XX_HIT` (el payload llegó)
- cualquier `5xx` → SECURITY, `critical/90`
- solo bloqueadas/redirigidas → ruido en OTHER (contexto, no impacto probado)

`recon_sensitive_file` requiere ≥2 respuestas correctas o un 10% de ratio de
éxito para no marcar escáneres 404 normales.

</details>

<details>
<summary><strong>Reglas de ruta agregada, rate / DDoS y tormentas de error</strong></summary>

| Prefijo ID | Categoría | Kind | Significado |
| --- | --- | --- | --- |
| `abusive_crawl:` | `abusive_crawling` | saturation/noise | presión servida o crawling distribuido en ruta no-entrypoint |
| `query_explosion:` | `abusive_crawling` | noise | una ruta con muchas variantes de query |
| `post_hotspot:` | `post_hotspot` | noise | endpoint con un número inusual de POSTs |
| `ddos_rps_burst_single_ip:` | `ddos` | saturation | una IP supera RPS por segundo durante segundos consecutivos |
| `ddos_global_rps_spike` | `ddos` | saturation | RPS global sobre la línea base durante segundos consecutivos |
| `http_head_flood:` | `ddos` | saturation | una IP con alto ratio + pico de peticiones HEAD |
| `ddos_distributed_subnet:` | `ddos` | saturation | IPv4 `/24` o IPv6 `/48` sobre umbrales de RPS + IPs únicas |
| `http_4xx_storm:` | `http_anomaly` | noise | una IP, muchas 4xx en buckets de minuto adyacentes |
| `http_5xx_storm:` | `http_anomaly` | saturation | una IP, muchas 5xx en buckets de minuto adyacentes |

</details>

<details>
<summary><strong>Reglas de bots y escáneres</strong></summary>

| Prefijo ID | Categoría | Kind | Significado |
| --- | --- | --- | --- |
| `ai_scraper_known:` | `ai_scraper` | saturation/noise | UA conocido de crawler/asistente de IA, agrupado por bot |
| `scanner_ua_known:` | `scanner` | compromise | UA conocido de escáner/herramienta ofensiva |
| `scanner_signature_paths:` | `scanner` | compromise | una IP toca muchas rutas de fingerprint |
| `single_ip_path_explosion:` | `abusive_crawling` | saturation | una IP > 10 rutas únicas/minuto sostenido |
| `ua_rotation_same_ip:` | `http_anomaly` | noise | una IP, muchos UAs **y** pico RPS ≥ 5 |
| `fake_bot_googlebot:` | `fake_bot` | compromise | dice ser Googlebot pero la IP está fuera de rangos publicados |
| `fake_bot_bingbot:` | `fake_bot` | compromise | dice ser bingbot pero la IP está fuera de rangos de Bing |

Notas: `single_ip_path_explosion` exige **pathsPerMinute ≥ 10** (cargas de
página con muchos assets no lo disparan). `abusive_crawl` entra en SATURATION
solo con volumen real servido + un pico servido por minuto. `fake_bot_*` exige
≥10 peticiones. Las IPs verificadas de Googlebot/Bingbot quedan excluidas de
toda detección de bots/escáneres.

Actualiza los snapshots de rangos IP de Googlebot/Bingbot con:

```bash
pnpm run update-bot-ranges
```

</details>

---

## 🎯 Puntuación

Cada incidente tiene `kind`, `severity`, `score` (0–100), `evidence` tipada,
`samples` redactadas y `successful?`.

| Score | Severidad |
| --- | --- |
| 0–24 | `info` |
| 25–49 | `low` |
| 50–74 | `medium` |
| 75–89 | `high` |
| 90–100 | `critical` |

Multiplicadores de post-procesado:

- `+10` cuando la misma `evidence.ip` aparece en ≥2 incidentes (atacante correlado)
- `+15` cuando un patrón persiste ≥30 min (bonus de persistencia)
- `−10` para crawlers de IA moderados que pidieron `robots.txt`

El bonus de persistencia **no** aplica a `ai_scraper_known:*` — los crawlers de
IA corren durante semanas, así que la duración por sí sola no es señal. Los
paneles ordenan por peso de `kind` (compromise → saturation → noise) y luego por
score descendente.

---

## 🔒 Seguridad y privacidad

- **Análisis local primero** — sin llamadas de red durante el análisis.
- **Sin telemetría**, nunca. (Si alguna vez se añade, será opt-in estricto.)
- **IA solo al pulsar `a`**, con contexto redactado.
- **Secretos redactados** en valores de URL/query:
  `token, _token, sid, session, password, passwd, key, secret, jwt, auth, authorization`
- **Salida HTML escapada**; el contenido del log nunca se ejecuta.
- El **índice temporal** de la TUI se borra al salir.

Trata logs, JSON exportado, rutas, IPs y nombres de ruta como **datos sensibles
de cliente** — mantenlos fuera de commits públicos.

---

## 🛠️ Desarrollo

```bash
pnpm install
pnpm run typecheck
pnpm test
pnpm run build

# ejecutar desde el código contra un fixture
pnpm run dev -- examples/your.log
pnpm run dev -- examples/your.log --json
```

Estructura del proyecto:

```
input/    descubrimiento de rutas, stdin, lectores comprimidos/archivos
parser/   detección de formato, registro de parsers, parsers integrados + custom
analysis/ agregación en streaming, seguimiento de comportamiento, match sets
rules/    reglas deterministas de request/path y puntuación
run/      workspace temporal de ejecución e índice de log
tui/      pantallas Ink, hooks, filtros, tablas, overlays
ai/       constructor de contexto compacto redactado + cliente OpenAI
report/   renderers de terminal, JSON, Markdown, HTML
```

**Stack:** TypeScript (ESM) · `commander` · `ink` + React · `zod` ·
`picocolors` · SDK oficial de `openai` · Vitest.

---

## 📄 Licencia

[MIT](./LICENSE) © [javipm](https://github.com/javipm)

<div align="center">
<sub>Hecho para quien lee sus logs de acceso. 🍋</sub>
</div>
