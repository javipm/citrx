import type { IncidentLogLine } from "../analysis/types.js";
import { requestParamEntries } from "../analysis/query-params.js";

type BinaryOperator = "and" | "or";
type MatchOperator = ":" | "=" | "!=" | ">" | ">=" | "<" | "<=";

type FilterExpression =
  | { kind: "term"; term: FilterTerm }
  | { kind: "not"; expression: FilterExpression }
  | { kind: "binary"; operator: BinaryOperator; left: FilterExpression; right: FilterExpression };

type FilterTerm =
  | { kind: "text"; value: string }
  | { kind: "field"; field: FilterField; operator: MatchOperator; value: string };

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

export class AccessLogFilterSyntaxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccessLogFilterSyntaxError";
  }
}

export function createAccessLogLineFilter(query: string): (line: IncidentLogLine) => boolean {
  const expression = parseAccessLogFilter(query);

  if (!expression) {
    return () => true;
  }

  return (line) => evaluateExpression(expression, line);
}

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

function parseAccessLogFilter(query: string): FilterExpression | undefined {
  const tokens = tokenize(query);

  if (tokens.length === 0) {
    return undefined;
  }

  const parser = new FilterParser(tokens);
  return parser.parse();
}

class FilterParser {
  private index = 0;

  constructor(private readonly tokens: Token[]) {}

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

function normalizeField(value: string): FilterField | undefined {
  return FIELD_ALIASES[value] ?? FIELD_ALIASES[value.toLowerCase()];
}

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

function queryEntries(target: string): Array<[string, string]> {
  return requestParamEntries(target).map((entry) => [entry.name, entry.value]);
}

function matchPattern(actualValue: string, expectedValue: string, containsByDefault: boolean): boolean {
  const actual = actualValue.toLowerCase();
  const expected = safeDecode(expectedValue).toLowerCase();

  if (hasWildcard(expected)) {
    return wildcardRegex(expected).test(actual);
  }

  return containsByDefault ? actual.includes(expected) : actual === expected;
}

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

function hasWildcard(value: string): boolean {
  return value.includes("*");
}

function isStatusFamily(value: string): boolean {
  return /^[1-5]xx$/i.test(value);
}

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

function isNumericField(field: FilterField): field is "bytes" | "line" | "status" {
  return field === "bytes" || field === "line" || field === "status";
}

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

function queryString(target: string): string {
  const queryStart = target.indexOf("?");
  return queryStart === -1 ? "" : target.slice(queryStart + 1);
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function isWordOperator(token: Token | undefined, operator: "and" | "or" | "not"): boolean {
  return typeof token === "object" && token.value.toLowerCase() === operator;
}

function tokenLabel(token: Token | undefined): string {
  if (!token) {
    return "end of filter";
  }

  return typeof token === "string" ? token : token.value;
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+*?.]/g, "\\$&");
}
