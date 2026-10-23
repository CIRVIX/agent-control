/**
 * Structural classification of a SQL statement.
 *
 * WHY THIS EXISTS
 *
 * The risk engine used to decide whether a database call was a read by asking
 * two questions: does the *tool name* end in `query`, and does the *string*
 * contain `insert|update|delete|upsert|merge|alter|create`? Both answers are
 * wrong in the direction that matters:
 *
 *   - A tool named `sql_query` normalizes to `db.read`, so `allow: tool =
 *     database.query` permits whatever the caller puts in it. `DROP TABLE
 *     users` is not a read, but it arrived through a tool whose name said it
 *     was, and no rule could tell the difference.
 *   - `drop`, `truncate`, `grant` and `revoke` were not in the regex at all,
 *     so the most destructive statements in the language scored LOW.
 *   - `SELECT 1; DROP TABLE users` contains no leading destructive verb at the
 *     position a substring search inspects, and `WITH x AS (...) DELETE FROM
 *     y` contains none at all.
 *
 * A regex over raw text cannot answer this. The statement has to be
 * tokenized: comments and string literals removed so a `--` or a `'DROP'`
 * inside a value cannot hide or fabricate a verb, split on statement
 * boundaries, and each statement's *governing* verb resolved — including
 * through a CTE, where the verb is behind the `WITH` clause and its
 * parenthesized bodies.
 *
 * FAIL CLOSED
 *
 * An unrecognised or unparseable statement is not a read. It is `unknown`,
 * which the risk engine treats as a write and policy treats as needing a
 * human. The only statements that come back `read` are ones whose governing
 * verb is provably read-only.
 *
 * This is a classifier, not a parser: it deliberately does not model dialects,
 * so a statement it cannot read is refused rather than guessed at. The
 * database's own least-privilege credentials are the second line of defence
 * behind it.
 */

/** Verbs that inspect without changing anything. */
const READ_VERBS = new Set(["select", "table", "values", "show", "describe", "desc"]);

/** Verbs that change data or schema. Held for a human, never silently allowed. */
const WRITE_VERBS = new Set([
  "insert",
  "update",
  "delete",
  "merge",
  "upsert",
  "replace",
  "create",
  "load",
  "import",
  "set",
  "pragma",
  "vacuum",
  "analyze",
  "analyse",
  "reindex",
  "cluster",
  "refresh",
  "reset",
  "move",
  "comment",
  "label",
  "lock",
  "listen",
  "notify",
  "prepare",
]);

/**
 * Verbs that destroy or redefine data, schema, or authority.
 *
 * `copy` is here rather than with the writes because `COPY ... TO PROGRAM`
 * runs a shell command on the server, and `copy` reads and writes files the
 * database process can reach. `call`, `do`, `execute` and `exec` are here
 * because a stored procedure's side effects cannot be seen from its name —
 * which is exactly the case the classifier must refuse rather than assume.
 */
const DESTRUCTIVE_VERBS = new Set([
  "drop",
  "truncate",
  "alter",
  "grant",
  "revoke",
  "rename",
  "copy",
  "attach",
  "detach",
  "call",
  "do",
  "execute",
  "exec",
  "impersonate",
  "kill",
  "deny",
  "shutdown",
]);

/** Verbs with no effect on their own — transaction and session control. */
const BENIGN_VERBS = new Set([
  "begin",
  "commit",
  "rollback",
  "start",
  "savepoint",
  "release",
  "end",
  "explain",
  "deallocate",
  "use",
  "discard",
]);

/** Severity order. `unknown` sits with `write`: it is never a read. */
const RANK = { read: 0, write: 1, unknown: 1, destructive: 2 };

export const SQL_KIND = Object.freeze({
  READ: "read",
  WRITE: "write",
  DESTRUCTIVE: "destructive",
  UNKNOWN: "unknown",
});

/** Every verb the classifier understands, for `looksLikeSql`. */
const ALL_VERBS = new Set([
  ...READ_VERBS,
  ...WRITE_VERBS,
  ...DESTRUCTIVE_VERBS,
  ...BENIGN_VERBS,
  "with",
]);

/**
 * Removes comments and replaces string literals with a marker.
 *
 * Both halves matter. A comment can contain a semicolon that would split a
 * statement in the wrong place, or a verb that would fabricate one, and a
 * literal can do the same (`SELECT 'DROP TABLE x'`). What survives is the SQL
 * the server will actually parse — no more and no less.
 */
function stripNoise(source) {
  let out = "";
  let i = 0;
  const n = source.length;

  while (i < n) {
    const c = source[i];
    const next = source[i + 1];

    // Line comments: `--` everywhere, `#` in MySQL.
    if ((c === "-" && next === "-") || c === "#") {
      while (i < n && source[i] !== "\n") i++;
      out += " ";
      continue;
    }

    // Block comments. PostgreSQL nests them; one level is what the dialects
    // that do not nest accept, and an unterminated one swallows the rest.
    if (c === "/" && next === "*") {
      i += 2;
      let depth = 1;
      while (i < n && depth > 0) {
        if (source[i] === "/" && source[i + 1] === "*") {
          depth++;
          i += 2;
        } else if (source[i] === "*" && source[i + 1] === "/") {
          depth--;
          i += 2;
        } else i++;
      }
      out += " ";
      continue;
    }

    // Quoted literals and identifiers. A doubled quote is an escaped quote.
    if (c === "'" || c === '"' || c === "`") {
      const quote = c;
      i++;
      while (i < n) {
        if (source[i] === "\\" && quote !== '"') {
          i += 2;
          continue;
        }
        if (source[i] === quote) {
          if (source[i + 1] === quote) {
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      out += " '' ";
      continue;
    }

    // Dollar-quoted strings: $$…$$ and $tag$…$tag$.
    if (c === "$") {
      const marker = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(source.slice(i, i + 64));
      if (marker) {
        const tag = marker[0];
        const close = source.indexOf(tag, i + tag.length);
        if (close !== -1) {
          i = close + tag.length;
          out += " '' ";
          continue;
        }
        // Unterminated: the remainder is one opaque literal.
        out += " '' ";
        break;
      }
    }

    out += c;
    i++;
  }

  return out;
}

/** Words, parentheses and commas only — everything else is a separator. */
function tokenize(fragment) {
  const tokens = [];
  const re = /[A-Za-z_][A-Za-z0-9_$]*|[()]|,/g;
  let m;
  while ((m = re.exec(fragment)) !== null) tokens.push(m[0]);
  return tokens;
}

/** Index just past the balanced group starting at `tokens[i] === "("`. */
function skipGroup(tokens, i) {
  if (tokens[i] !== "(") return i;
  let depth = 0;
  while (i < tokens.length) {
    if (tokens[i] === "(") depth++;
    else if (tokens[i] === ")") {
      depth--;
      if (depth === 0) return i + 1;
    }
    i++;
  }
  return tokens.length;
}

/**
 * Index of the first token after a leading `WITH … AS (…) [, …]` CTE list.
 *
 * The verb of `WITH x AS (SELECT 1) DELETE FROM y` is `delete`, and it is
 * behind an arbitrary number of parenthesized bodies. Skipping the CTE list is
 * what lets the classifier see it; nothing else in the statement can name a
 * verb, because a CTE's `AS (…)` group is skipped whole.
 */
function skipCtes(tokens, start) {
  let i = start;
  while (i < tokens.length) {
    const token = tokens[i];
    // A CTE name — an identifier that is not itself a statement verb.
    if (!/^[A-Za-z_]/.test(token) || ALL_VERBS.has(token.toLowerCase())) break;
    i++;
    // Optional column list.
    if (tokens[i] === "(") i = skipGroup(tokens, i);
    if ((tokens[i] ?? "").toLowerCase() !== "as") break;
    i++;
    if ((tokens[i] ?? "").toLowerCase() === "not") i++;
    if ((tokens[i] ?? "").toLowerCase() === "materialized") i++;
    if (tokens[i] !== "(") break;
    i = skipGroup(tokens, i);
    if (tokens[i] === ",") {
      i++;
      continue;
    }
    break;
  }
  return i;
}

/** The verbs that govern one statement. Empty when nothing recognisable leads. */
function governingVerbs(fragment) {
  const tokens = tokenize(fragment);
  if (!tokens.length) return [];

  let i = 0;
  // A leading parenthesis is a wrapped statement: `(SELECT 1) UNION (…)`.
  while (tokens[i] === "(") i++;
  while (tokens[i] === ",") i++;

  if ((tokens[i] ?? "").toLowerCase() === "with") {
    i++;
    if ((tokens[i] ?? "").toLowerCase() === "recursive") i++;
    i = skipCtes(tokens, i);
    while (tokens[i] === "(" || tokens[i] === ",") i++;
  }

  const verbs = [];
  const first = (tokens[i] ?? "").toLowerCase();
  if (!first) return [];

  verbs.push(first);

  /*
   * `EXPLAIN` and `EXPLAIN ANALYZE` are the only place a statement has two
   * verbs, and the second one is what runs. `EXPLAIN ANALYZE UPDATE …` writes;
   * `EXPLAIN SELECT …` does not. `analyze` is dropped from the list rather
   * than counted, so the read form stays a read.
   */
  if (first === "explain") {
    let j = i + 1;
    for (const wrapper of ["analyze", "analyse", "verbose", "buffers", "format"]) {
      if ((tokens[j] ?? "").toLowerCase() === wrapper) j++;
    }
    if ((tokens[j] ?? "").toLowerCase() !== "select") {
      const inner = (tokens[j] ?? "").toLowerCase();
      if (inner) verbs.push(inner);
    }
  }

  return verbs;
}

function kindOf(verb) {
  if (!verb) return null;
  if (READ_VERBS.has(verb) || BENIGN_VERBS.has(verb)) return SQL_KIND.READ;
  if (WRITE_VERBS.has(verb)) return SQL_KIND.WRITE;
  if (DESTRUCTIVE_VERBS.has(verb)) return SQL_KIND.DESTRUCTIVE;
  return null;
}

function maxKind(a, b) {
  return (RANK[b] ?? 0) > (RANK[a] ?? 0) ? b : a;
}

/**
 * Classify a SQL statement (or a batch of them).
 *
 * Returns the most severe kind found across every statement in the batch, so
 * `SELECT 1; DROP TABLE users` is `destructive` — an appended statement cannot
 * ride in behind a read.
 *
 * @param {string} source
 * @returns {{kind: string, verbs: string[], statements: number, reason: string}}
 */
export function analyzeSql(source) {
  if (typeof source !== "string" || !source.trim()) {
    return { kind: "empty", verbs: [], statements: 0, reason: "There is no statement to classify." };
  }

  const clean = stripNoise(source);
  const fragments = clean
    .split(";")
    .map((f) => f.trim())
    .filter((f) => f.length > 0);

  if (!fragments.length) {
    return { kind: "empty", verbs: [], statements: 0, reason: "There is no statement to classify." };
  }

  const verbs = [];
  let kind = SQL_KIND.READ;
  let sawKnown = false;

  for (const fragment of fragments) {
    const governing = governingVerbs(fragment);
    const kinds = governing.map(kindOf).filter(Boolean);
    if (!kinds.length) {
      // A statement whose verb is not in the table is not a read. Refuse it.
      kind = maxKind(kind, SQL_KIND.UNKNOWN);
      continue;
    }
    sawKnown = true;
    for (const k of kinds) kind = maxKind(kind, k);
  }

  for (const fragment of fragments) {
    for (const v of governingVerbs(fragment)) if (!verbs.includes(v)) verbs.push(v);
  }

  if (!sawKnown) kind = SQL_KIND.UNKNOWN;

  const reason = {
    [SQL_KIND.READ]: "Reads state without changing it.",
    [SQL_KIND.WRITE]: "Changes data or schema.",
    [SQL_KIND.DESTRUCTIVE]: "Destroys or redefines data, schema, or authority rather than reading it.",
    [SQL_KIND.UNKNOWN]: "The statement's effect could not be established, so it is treated as a write.",
  }[kind];

  return { kind, verbs, statements: fragments.length, reason };
}

/** True when `kind` is at least `floor`. Unknown ranks with write. */
export function sqlKindAtLeast(kind, floor) {
  return (RANK[kind] ?? 0) >= (RANK[floor] ?? 0);
}

/** True when the canonical "read-only" action must be escalated. */
export function isReadEscalating(kind) {
  return kind === SQL_KIND.WRITE || kind === SQL_KIND.DESTRUCTIVE || kind === SQL_KIND.UNKNOWN;
}

/**
 * True when the text plausibly is SQL.
 *
 * Used only for the resource fallback — a tool that runs SQL but passed the
 * statement as its resource. Deliberately conservative: a table name is not a
 * statement, and treating it as one would turn every `SELECT` against a table
 * into an unclassifiable write.
 */
export function looksLikeSql(text) {
  if (typeof text !== "string") return false;
  const clean = stripNoise(text).trim();
  if (!clean) return false;
  if (clean.startsWith("(")) return true;
  const first = /^[A-Za-z_][A-Za-z0-9_]*/.exec(clean);
  if (!first) return false;
  const verb = first[0].toLowerCase();
  if (ALL_VERBS.has(verb)) return true;
  // `SELECT`'s cousins that are not verbs: `EXPLAIN ANALYZE` handled above,
  // plus the MySQL/PG introspection forms.
  return /^(pg_|information_schema|pg_catalog)/i.test(verb);
}

/** True when a tool name says it runs SQL, whatever verb it is spelled with. */
export function isSqlTool(name) {
  const s = String(name ?? "");
  if (/sql/i.test(s)) return true;
  return /(^|[._\- ])(db|database|postgres|postgresql|mysql|mariadb|sqlite|mssql|clickhouse|snowflake|bigquery|redshift|oracle|duckdb)([._\- ]|$)/i.test(s);
}
