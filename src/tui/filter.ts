import type { IncidentLogLine } from "../analysis/types.js";
import { requestParamEntries } from "../analysis/query-params.js";

/** Logical combinator joining two sub-expressions. */
type BinaryOperator = "and" | "or";

/** Operator used between a field name and its match value. `:` = contains, `=` = exact, `!=` = negation, `>/<` = numeric comparison. */
type MatchOperator = ":" | "=" | "!=" | ">" | ">=" | "<" | "<=";

/** AST node for a parsed filter expression. */
type FilterExpression =
  | { kind: "term"; term: FilterTerm }
  | { kind: "not"; expression: FilterExpression }
  | { kind: "binary"; operator: BinaryOperator; left: FilterExpression; right: FilterExpression };

/** Leaf node of the AST: either a bare text search or a field-scoped match. */
type FilterTerm =
  | { kind: "text"; value: string }
  | { kind: "field"; field: FilterField; operator: MatchOperator; value: string };

/** Canonical internal field identifiers used after alias resolution. */
type FilterField =
  | "bytes"
  | "ip"
  | "line"
  | "method"
  | "param"
  | "path"
  | "query"
  | "raw"
  | "source"
  | "status"
  | "target"
  | "time"
  | "ua";

/** A single token produced by the tokenizer: a punctuation symbol or a word value. */
type Token = "(" | ")" | "|" | "!" | { value: string };

const FIELD_ALIASES: Record<string, FilterField> = {
  bytes: "bytes",
  ip: "ip",
  line: "line",
  lineNumber: "line",
  ln: "line",
  method: "method",
  mth: "method",
  param: "param",
  params: "param",
  path: "path",
  query: "query",
  qs: "query",
  raw: "raw",
  source: "source",
  src: "source",
  status: "status",
  st: "status",
  target: "target",
  time: "time",
  timestamp: "time",
  ua: "ua",
  url: "target",
  userAgent: "ua"
};

/** Thrown when a filter query string cannot be parsed due to invalid syntax. */
export class AccessLogFilterSyntaxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccessLogFilterSyntaxError";
  }
}

/**
 * Compiles a filter query string into a predicate function.
 *
 * Parses the query using the recursive descent parser, then returns a function
 * that evaluates each `IncidentLogLine` against the resulting AST. An empty or
 * blank query returns a predicate that accepts every line.
 *
 * @param query - Filter expression, e.g. `"status:5xx AND path:/api"`.
 * @returns A predicate `(line) => boolean` ready for use in `.filter()` calls.
 * @throws {AccessLogFilterSyntaxError} If the query cannot be parsed.
 */
export function createAccessLogLineFilter(query: string): (line: IncidentLogLine) => boolean {
  const expression = parseAccessLogFilter(query);

  if (!expression) {
    return () => true;
  }

  return (line) => evaluateExpression(expression, line);
}

/**
 * Validates a filter query string without producing a predicate.
 *
 * Attempts to parse the query and returns `{ ok: true }` on success or
 * `{ ok: false; error: string }` with a human-readable message on failure.
 * Does not throw.
 *
 * @param query - Filter expression to validate.
 * @returns `{ ok: true }` if valid, or `{ ok: false; error }` if not.
 */
export function validateAccessLogFilter(query: string): { ok: true } | { ok: false; error: string } {
  try {
    parseAccessLogFilter(query);
    return { ok: true };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

/**
 * Tokenizes and parses a raw query string into a `FilterExpression` AST.
 * Returns `undefined` for an empty token stream (blank query).
 */
function parseAccessLogFilter(query: string): FilterExpression | undefined {
  const tokens = tokenize(query);

  if (tokens.length === 0) {
    return undefined;
  }

  const parser = new FilterParser(tokens);
  return parser.parse();
}

/**
 * Recursive descent parser that converts a flat `Token[]` stream into a
 * `FilterExpression` AST. Precedence (low → high): OR → AND → NOT → primary.
 */
class FilterParser {
  private index = 0;

  constructor(private readonly tokens: Token[]) {}

  /** Entry point: parses the full expression and asserts the token stream is exhausted. */
  parse(): FilterExpression {
    const expression = this.parseOr();

    if (this.peek()) {
      throw new AccessLogFilterSyntaxError(`unexpected token "${tokenLabel(this.peek())}"`);
    }

    return expression;
  }

  private parseOr(): FilterExpression {
    let expression = this.parseAnd();

    while (this.matchOperator("or") || this.match("|")) {
      expression = {
        kind: "binary",
        operator: "or",
        left: expression,
        right: this.parseAnd()
      };
    }

    return expression;
  }

  private parseAnd(): FilterExpression {
    let expression = this.parseUnary();

    while (this.startsExpression()) {
      this.matchOperator("and");
      expression = {
        kind: "binary",
        operator: "and",
        left: expression,
        right: this.parseUnary()
      };
    }

    return expression;
  }

  private parseUnary(): FilterExpression {
    if (this.match("!") || this.matchOperator("not")) {
      return {
        kind: "not",
        expression: this.parseUnary()
      };
    }

    return this.parsePrimary();
  }

  private parsePrimary(): FilterExpression {
    if (this.match("(")) {
      const expression = this.parseOr();

      if (!this.match(")")) {
        throw new AccessLogFilterSyntaxError("missing closing parenthesis");
      }

      return expression;
    }

    const token = this.consumeWord();

    if (!token) {
      throw new AccessLogFilterSyntaxError(`expected filter term, got "${tokenLabel(this.peek())}"`);
    }

    return {
      kind: "term",
      term: parseTerm(token.value)
    };
  }

  private startsExpression(): boolean {
    const token = this.peek();

    if (!token || token === ")" || token === "|" || isWordOperator(token, "or")) {
      return false;
    }

    return true;
  }

  private match(token: "(" | ")" | "|" | "!"): boolean {
    if (this.peek() !== token) {
      return false;
    }

    this.index += 1;
    return true;
  }

  private matchOperator(operator: "and" | "or" | "not"): boolean {
    const token = this.peek();

    if (!isWordOperator(token, operator)) {
      return false;
    }

    this.index += 1;
    return true;
  }

  private consumeWord(): { value: string } | undefined {
    const token = this.peek();

    if (!token || typeof token === "string") {
      return undefined;
    }

    this.index += 1;
    return token;
  }

  private peek(): Token | undefined {
    return this.tokens[this.index];
  }
}

/**
 * Splits a raw query string into a flat array of `Token` values.
 * Whitespace is skipped; `(`, `)`, `|`, and `!` (not followed by `=`) become
 * single-character punctuation tokens; everything else is collected into word
 * tokens (respecting single- and double-quoted spans).
 */
function tokenize(query: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;

  while (index < query.length) {
    const char = query[index];

    if (!char || /\s/.test(char)) {
      index += 1;
      continue;
    }

    if (char === "(" || char === ")" || char === "|") {
      tokens.push(char);
      index += 1;
      continue;
    }

    if (char === "!" && query[index + 1] !== "=") {
      tokens.push("!");
      index += 1;
      continue;
    }

    const result = readWord(query, index);
    tokens.push({ value: result.value });
    index = result.nextIndex;
  }

  return tokens;
}

/**
 * Reads a single unquoted word token (possibly containing quoted segments)
 * from `query` starting at `startIndex`. Stops at whitespace, `(`, `)`, or `|`.
 * @throws {AccessLogFilterSyntaxError} If the result is empty.
 */
function readWord(query: string, startIndex: number): { value: string; nextIndex: number } {
  let value = "";
  let index = startIndex;

  while (index < query.length) {
    const char = query[index];

    if (!char || /\s/.test(char) || char === "(" || char === ")" || char === "|") {
      break;
    }

    if (char === "'" || char === "\"") {
      const result = readQuoted(query, index);
      value += result.value;
      index = result.nextIndex;
      continue;
    }

    value += char;
    index += 1;
  }

  if (!value) {
    throw new AccessLogFilterSyntaxError("empty filter term");
  }

  return { value, nextIndex: index };
}

/**
 * Reads a single- or double-quoted string segment from `query` at `startIndex`,
 * handling `\`-escape sequences. Returns the unescaped content and the index
 * after the closing quote.
 * @throws {AccessLogFilterSyntaxError} If the closing quote is never found.
 */
function readQuoted(query: string, startIndex: number): { value: string; nextIndex: number } {
  const quote = query[startIndex];
  let value = "";
  let index = startIndex + 1;

  while (index < query.length) {
    const char = query[index];

    if (char === "\\") {
      value += query[index + 1] ?? "";
      index += 2;
      continue;
    }

    if (char === quote) {
      return { value, nextIndex: index + 1 };
    }

    value += char;
    index += 1;
  }

  throw new AccessLogFilterSyntaxError("unterminated quoted value");
}

/**
 * Parses a single word token into a `FilterTerm`. Checks for a known field
 * alias followed by a match operator (`!=`, `>=`, `<=`, `:`, `=`, `>`, `<`);
 * falls back to a bare text term if no valid field prefix is found.
 * @throws {AccessLogFilterSyntaxError} If a field operator has no value after it.
 */
function parseTerm(token: string): FilterTerm {
  for (const operator of ["!=", ">=", "<=", ":", "=", ">", "<"] as const) {
    const index = token.indexOf(operator);

    if (index <= 0) {
      continue;
    }

    const field = normalizeField(token.slice(0, index));

    if (!field) {
      continue;
    }

    const value = token.slice(index + operator.length);

    if (!value) {
      throw new AccessLogFilterSyntaxError(`missing value for "${token.slice(0, index)}"`);
    }

    return {
      kind: "field",
      field,
      operator,
      value
    };
  }

  return { kind: "text", value: token };
}

/**
 * Resolves a raw field name (or alias) to a canonical `FilterField`.
 * Tries the original casing first, then lowercase. Returns `undefined` if
 * the name is not a recognised alias.
 */
function normalizeField(value: string): FilterField | undefined {
  return FIELD_ALIASES[value] ?? FIELD_ALIASES[value.toLowerCase()];
}

/**
 * Recursively evaluates a `FilterExpression` AST node against a log line.
 * `not` negates its child; `binary` short-circuits AND/OR; `term` delegates
 * to `evaluateTerm`.
 */
function evaluateExpression(expression: FilterExpression, line: IncidentLogLine): boolean {
  switch (expression.kind) {
    case "term":
      return evaluateTerm(expression.term, line);
    case "not":
      return !evaluateExpression(expression.expression, line);
    case "binary":
      return expression.operator === "and"
        ? evaluateExpression(expression.left, line) && evaluateExpression(expression.right, line)
        : evaluateExpression(expression.left, line) || evaluateExpression(expression.right, line);
  }
}

/**
 * Evaluates a leaf `FilterTerm` against a log line.
 * - `text`: searches the full concatenated searchable representation.
 * - `param`: delegates to `matchParam` for query-string parameter matching.
 * - numeric fields (`bytes`, `line`, `status`): uses `matchNumericField`.
 * - all other fields: uses `matchPattern` with the field's string value.
 */
function evaluateTerm(term: FilterTerm, line: IncidentLogLine): boolean {
  if (term.kind === "text") {
    return matchPattern(searchableLine(line), term.value, true);
  }

  if (term.field === "param") {
    const result = matchParam(line.target, term.value, term.operator !== "!=");
    return term.operator === "!=" ? !result : result;
  }

  if (isNumericField(term.field)) {
    return matchNumericField(numericFieldValue(line, term.field), term.operator, term.value);
  }

  const actual = fieldValue(line, term.field);
  const matched = matchPattern(actual, term.value, term.operator === ":");

  return term.operator === "!=" ? !matched : matched;
}

/**
 * Compares a numeric field value against an expected string using the given
 * operator. `null` (missing) values match only `!=`. Recognises HTTP status
 * family patterns (`2xx`, `4xx`, etc.) for `:`, `=`, and `!=` operators;
 * non-numeric expected values fall back to `matchPattern`; numeric values use
 * standard arithmetic comparison.
 */
function matchNumericField(actual: number | null, operator: MatchOperator, expected: string): boolean {
  if (actual === null) {
    return operator === "!=";
  }

  if ((operator === ":" || operator === "=" || operator === "!=") && isStatusFamily(expected)) {
    const matched = Math.floor(actual / 100) === Number(expected[0]);
    return operator === "!=" ? !matched : matched;
  }

  const expectedNumber = Number(expected);

  if (!Number.isFinite(expectedNumber)) {
    const matched = matchPattern(String(actual), expected, operator === ":");
    return operator === "!=" ? !matched : matched;
  }

  switch (operator) {
    case ">":
      return actual > expectedNumber;
    case ">=":
      return actual >= expectedNumber;
    case "<":
      return actual < expectedNumber;
    case "<=":
      return actual <= expectedNumber;
    case "!=":
      return actual !== expectedNumber;
    case ":":
    case "=":
      return actual === expectedNumber;
  }
}

/**
 * Matches query-string parameters in `target` against `expected`.
 * `expected` may be a bare name pattern (matches any param with that name) or
 * `name=value` syntax (matches name and value independently; `*` as name
 * matches any param name). `positive` controls whether value matching is
 * contains (`true`) or exact (`false`).
 */
function matchParam(target: string, expected: string, positive: boolean): boolean {
  const entries = queryEntries(target);
  const separator = expected.indexOf("=");

  if (separator === -1) {
    return entries.some(([name]) => matchPattern(name, expected, false));
  }

  const namePattern = expected.slice(0, separator);
  const valuePattern = expected.slice(separator + 1);

  return entries.some(([name, value]) => {
    const nameMatches = namePattern === "*" || matchPattern(name, namePattern, false);
    const valueMatches = matchPattern(value, valuePattern, positive);
    return nameMatches && valueMatches;
  });
}

/** Extracts query-string parameter name/value pairs from a URL target string. */
function queryEntries(target: string): Array<[string, string]> {
  return requestParamEntries(target).map((entry) => [entry.name, entry.value]);
}

/**
 * Case-insensitive pattern match. If `expectedValue` contains `*` wildcards,
 * compiles a regex via `wildcardRegex`. Otherwise uses substring inclusion when
 * `containsByDefault` is `true`, or strict equality when `false`.
 * Both sides are lowercased; `expectedValue` is URI-decoded before comparison.
 */
function matchPattern(actualValue: string, expectedValue: string, containsByDefault: boolean): boolean {
  const actual = actualValue.toLowerCase();
  const expected = safeDecode(expectedValue).toLowerCase();

  if (hasWildcard(expected)) {
    return wildcardRegex(expected).test(actual);
  }

  return containsByDefault ? actual.includes(expected) : actual === expected;
}

/**
 * Converts a wildcard pattern (where `*` means "any characters") into a
 * case-insensitive anchored `RegExp`. All other regex special characters are
 * escaped before compilation.
 */
function wildcardRegex(value: string): RegExp {
  const pattern = value
    .split("")
    .map((char) => {
      if (char === "*") {
        return ".*";
      }

      return escapeRegex(char);
    })
    .join("");

  return new RegExp(`^${pattern}$`, "i");
}

/** Returns `true` if `value` contains at least one `*` wildcard character. */
function hasWildcard(value: string): boolean {
  return value.includes("*");
}

/** Returns `true` if `value` is an HTTP status-family pattern like `2xx`–`5xx`. */
function isStatusFamily(value: string): boolean {
  return /^[1-5]xx$/i.test(value);
}

/**
 * Extracts a string representation of a named field from a log line.
 * Numeric fields (`bytes`, `line`, `status`) are coerced via `String()`.
 * `query` returns only the query-string portion of `target`; `param` is
 * treated the same way here (real param matching uses `matchParam` directly).
 */
function fieldValue(line: IncidentLogLine, field: FilterField): string {
  switch (field) {
    case "ip":
      return line.ip;
    case "method":
      return line.method;
    case "path":
      return line.path;
    case "query":
      return queryString(line.target);
    case "raw":
      return line.raw;
    case "source":
      return line.source;
    case "target":
      return line.target;
    case "time":
      return line.timestamp;
    case "ua":
      return line.userAgent ?? "";
    case "bytes":
    case "line":
    case "param":
    case "status":
      return String(numericFieldValue(line, field) ?? "");
  }
}

/** Type-guard: returns `true` for fields that carry numeric values (`bytes`, `line`, `status`). */
function isNumericField(field: FilterField): field is "bytes" | "line" | "status" {
  return field === "bytes" || field === "line" || field === "status";
}

/** Returns the raw numeric value for `bytes`, `line`, or `status` fields; `null` for all others. */
function numericFieldValue(line: IncidentLogLine, field: FilterField): number | null {
  switch (field) {
    case "bytes":
      return line.bytes;
    case "line":
      return line.lineNumber;
    case "status":
      return line.status;
    default:
      return null;
  }
}

/**
 * Builds a single lowercased string concatenating all searchable fields of a
 * log line (ip, timestamp, method, path, target, status, bytes, userAgent, raw)
 * for use by bare text-term matching.
 */
function searchableLine(line: IncidentLogLine): string {
  return [
    line.ip,
    line.timestamp,
    line.method,
    line.path,
    line.target,
    line.status,
    line.bytes,
    line.userAgent,
    line.raw
  ]
    .join(" ")
    .toLowerCase();
}

/** Extracts the query string (without the leading `?`) from a URL target, or `""` if absent. */
function queryString(target: string): string {
  const queryStart = target.indexOf("?");
  return queryStart === -1 ? "" : target.slice(queryStart + 1);
}

/** URI-decodes `value` (replacing `+` with space), returning the original string on error. */
function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

/** Returns `true` if `token` is a word token whose value (case-insensitive) equals `operator`. */
function isWordOperator(token: Token | undefined, operator: "and" | "or" | "not"): boolean {
  return typeof token === "object" && token.value.toLowerCase() === operator;
}

/** Returns a human-readable label for a token for use in error messages. `undefined` → `"end of filter"`. */
function tokenLabel(token: Token | undefined): string {
  if (!token) {
    return "end of filter";
  }

  return typeof token === "string" ? token : token.value;
}

/** Escapes all regex special characters in `value` so it can be embedded in a `RegExp` pattern. */
function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+*?.]/g, "\\$&");
}
