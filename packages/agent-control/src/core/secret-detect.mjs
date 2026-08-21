/**
 * Secret detection — v1.
 *
 * Finds credential material in a string or a JSON structure: tool arguments on
 * the way out, tool results on the way back, a file an agent just read.
 *
 * THE RULE THIS MODULE OBEYS, ABOVE ALL OTHERS
 *
 * A finding NEVER contains the secret. Not in a field, not in a preview, not
 * "just the first few characters plus the length". Findings are written to the
 * audit chain, shipped to the control plane, and printed in terminals that
 * scroll into CI logs — a detector that carries the value it detected has
 * copied every credential it ever found into three new places, and it will be
 * the highest-severity finding in its own next scan.
 *
 * So each finding carries: what kind of secret, where it was, how long it was,
 * a masked shape (`AKIA••••••••••••EXMP`), and a SHA-256 fingerprint. The
 * fingerprint is enough to answer "is this the same secret as the one in that
 * other finding" — which is the only question anyone actually asks — without
 * ever holding the answer.
 *
 * DETECTION IS PATTERN PLUS SHAPE, NOT ENTROPY ALONE
 *
 * Pure entropy scanning finds minified JavaScript, base64 images, UUIDs, git
 * SHAs, and lockfile integrity hashes. On a real repository it is mostly false
 * positives, and a detector an operator learns to ignore is worse than none.
 *
 * So the strong signal is a *prefixed* pattern — `AKIA`, `ghp_`, `sk-ant-`,
 * `xoxb-` — where the issuer stamped the credential with something unambiguous.
 * Those fire on their own. Generic high-entropy strings only fire when they sit
 * next to an assignment whose *name* says credential (`API_KEY=`,
 * `"password":`), and even then they must clear an entropy floor. That pairing
 * is what keeps the false-positive rate low enough that the tool stays on.
 */

import { createHash } from "node:crypto";

/** Below this, a random-looking string is usually a word, a path, or a hash. */
const ENTROPY_FLOOR = 3.6;

/** A generic candidate shorter than this is noise. */
const MIN_GENERIC_LENGTH = 16;

/** Depth cap on the structure walk. */
const MAX_DEPTH = 12;

/** Cap on scanned length — a multi-megabyte file must not stall the hot path. */
const MAX_SCAN_BYTES = 1_000_000;

export const SEVERITY = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium" };

/* -------------------------------------------------------------------------- */
/*  Detectors                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Each detector is `{ id, name, severity, pattern, group?, validate? }`.
 *
 * `pattern` must be global. `group` names the capture holding the secret when
 * the match includes surrounding context (an assignment, a URL). `validate`
 * gets the candidate and rejects obvious non-secrets — placeholders, examples,
 * and the literal string `REDACTED`, which appears in exactly the documents
 * people scan.
 */
export const DETECTORS = [
  /* ------------------------------------------------------------------- cloud */
  {
    id: "aws-access-key-id",
    name: "AWS access key ID",
    severity: SEVERITY.CRITICAL,
    pattern: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
  },
  {
    id: "aws-secret-access-key",
    name: "AWS secret access key",
    severity: SEVERITY.CRITICAL,
    // Only with the name adjacent: 40 chars of base64 alone is far too common.
    pattern:
      /aws_?secret_?access_?key["'\s:=]+["']?([A-Za-z0-9/+=]{40})["']?/gi,
    group: 1,
  },
  {
    id: "aws-session-token",
    name: "AWS session token",
    severity: SEVERITY.CRITICAL,
    pattern: /aws_?session_?token["'\s:=]+["']?([A-Za-z0-9/+=]{100,})["']?/gi,
    group: 1,
  },
  {
    id: "gcp-api-key",
    name: "Google API key",
    severity: SEVERITY.HIGH,
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
  },
  {
    id: "gcp-service-account",
    name: "GCP service-account private key",
    severity: SEVERITY.CRITICAL,
    pattern: /"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key"\s*:\s*"(-----BEGIN[^"]+)"/g,
    group: 1,
  },
  {
    id: "azure-storage-key",
    name: "Azure storage account key",
    severity: SEVERITY.CRITICAL,
    pattern: /AccountKey=([A-Za-z0-9+/=]{86}==)/g,
    group: 1,
  },

  /* ------------------------------------------------------------------- vcs */
  {
    id: "github-token",
    name: "GitHub token",
    severity: SEVERITY.CRITICAL,
    pattern: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b/g,
  },
  {
    id: "github-fine-grained-pat",
    name: "GitHub fine-grained PAT",
    severity: SEVERITY.CRITICAL,
    pattern: /\b(github_pat_[A-Za-z0-9_]{60,255})\b/g,
  },
  {
    id: "gitlab-token",
    name: "GitLab token",
    severity: SEVERITY.CRITICAL,
    pattern: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g,
  },

  /* ------------------------------------------------------------------- llm */
  {
    id: "openai-api-key",
    name: "OpenAI API key",
    severity: SEVERITY.CRITICAL,
    pattern: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b/g,
    // `sk-ant-` is Anthropic and has its own detector; do not double-report.
    validate: (v) => !v.startsWith("sk-ant-"),
  },
  {
    id: "anthropic-api-key",
    name: "Anthropic API key",
    severity: SEVERITY.CRITICAL,
    pattern: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g,
  },
  {
    id: "huggingface-token",
    name: "Hugging Face token",
    severity: SEVERITY.HIGH,
    pattern: /\b(hf_[A-Za-z0-9]{30,})\b/g,
  },

  /* ---------------------------------------------------------------- payments */
  {
    id: "stripe-secret-key",
    name: "Stripe secret key",
    severity: SEVERITY.CRITICAL,
    pattern: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b/g,
  },

  /* ------------------------------------------------------------------- comms */
  {
    id: "slack-token",
    name: "Slack token",
    severity: SEVERITY.HIGH,
    pattern: /\b(xox[abposr]-[A-Za-z0-9-]{10,})\b/g,
  },
  {
    id: "slack-webhook",
    name: "Slack webhook URL",
    severity: SEVERITY.HIGH,
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_+/-]{8,})/g,
  },
  {
    id: "sendgrid-key",
    name: "SendGrid API key",
    severity: SEVERITY.HIGH,
    pattern: /\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b/g,
  },
  {
    id: "twilio-key",
    name: "Twilio account SID",
    severity: SEVERITY.HIGH,
    pattern: /\b(AC[a-f0-9]{32})\b/g,
  },

  /* ------------------------------------------------------------------ crypto */
  {
    id: "private-key",
    name: "Private key",
    severity: SEVERITY.CRITICAL,
    pattern:
      /(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END[^-]*-----)/g,
  },
  {
    id: "ssh-private-key-header",
    name: "SSH private key",
    severity: SEVERITY.CRITICAL,
    // A truncated key is still a disclosure and still worth blocking.
    pattern: /(-----BEGIN OPENSSH PRIVATE KEY-----)/g,
  },
  {
    id: "jwt",
    name: "JSON Web Token",
    severity: SEVERITY.MEDIUM,
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
  },

  /* ---------------------------------------------------------------- database */
  {
    id: "database-url",
    name: "Database connection string with password",
    severity: SEVERITY.CRITICAL,
    pattern:
      /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|clickhouse):\/\/[^\s:@/]+:[^\s@/]{3,}@[^\s/"']+)/gi,
    validate: (v) => !/:(password|pass|secret|changeme|xxx+|\*+|<[^>]*>)@/i.test(v),
  },
  {
    id: "npm-token",
    name: "npm token",
    severity: SEVERITY.HIGH,
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/g,
  },

  /* ----------------------------------------------------------------- generic */
  {
    id: "credential-assignment",
    name: "Credential in an assignment",
    severity: SEVERITY.HIGH,
    /**
     * The one detector that needs entropy. It fires on `NAME = value` where the
     * *name* claims credential and the *value* looks random. Both halves are
     * required: `API_KEY=changeme` is not a leak and neither is a random string
     * assigned to `hash`.
     */
    pattern:
      /\b([A-Za-z0-9_.-]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET|AUTH|CREDENTIAL)[A-Za-z0-9_.-]*)\s*[:=]\s*["']?([^\s"',;}]{12,})["']?/gi,
    group: 2,
    nameGroup: 1,
    validate: (v) => isHighEntropy(v) && !isPlaceholder(v),
  },
  {
    id: "authorization-header",
    name: "Authorization header",
    severity: SEVERITY.HIGH,
    pattern: /authorization["'\s:=]+["']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{16,})["']?/gi,
    group: 1,
    validate: (v) => !isPlaceholder(v),
  },
];

/* -------------------------------------------------------------------------- */
/*  Heuristics                                                                 */
/* -------------------------------------------------------------------------- */

/** Shannon entropy in bits per character. */
export function entropy(value) {
  const s = String(value);
  if (!s.length) return 0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

export function isHighEntropy(value, floor = ENTROPY_FLOOR) {
  const s = String(value);
  if (s.length < MIN_GENERIC_LENGTH) return false;
  return entropy(s) >= floor;
}

/**
 * Strings that look like secrets and are not.
 *
 * This list is the difference between a tool developers keep on and one they
 * turn off in week two. Every entry here was a false positive somebody hit.
 */
const PLACEHOLDER =
  /^(?:x{3,}|\*{3,}|\.{3,}|-{3,}|0{6,}|<[^>]*>|\$\{[^}]*\}|%[A-Z_]+%|\{\{[^}]*\}\}|your[-_.]?|my[-_.]?|example|sample|placeholder|dummy|fake|test|changeme|redacted|removed|hidden|secret|password|todo|tbd|null|none|undefined|insert[-_]?)/i;

const KNOWN_NON_SECRET =
  /^(?:[0-9a-f]{7,8}|[0-9a-f]{40}|[0-9a-f]{64}|sha\d{3}-|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

export function isPlaceholder(value) {
  const s = String(value).trim();
  if (!s) return true;
  if (PLACEHOLDER.test(s)) return true;
  // A git SHA, an integrity hash, or a UUID. High entropy, not a credential.
  if (KNOWN_NON_SECRET.test(s)) return true;
  // A single repeated character, however long.
  if (/^(.)\1+$/.test(s)) return true;
  return false;
}

/* -------------------------------------------------------------------------- */
/*  Findings                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * A stable identity for a secret that is not the secret.
 *
 * Truncated to 16 hex characters: enough to make a collision irrelevant at any
 * volume a single machine produces, short enough to read in a terminal. It is
 * an unsalted hash of a high-entropy value, which is not a reversal risk in the
 * way an unsalted hash of a *password* would be.
 */
export function fingerprint(value) {
  return "sha256:" + createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
}

/**
 * A shape the operator can recognise without the value being present.
 *
 * Keeps the issuer prefix, because that is the part that identifies which
 * system to go rotate, and the last four, because that is what consoles show.
 * Everything between becomes bullets. A short value shows nothing at all.
 */
export function mask(value) {
  const s = String(value);
  if (s.length <= 8) return "•".repeat(s.length);
  const prefixMatch = s.match(/^((?:AKIA|ASIA|gh[pousr]_|github_pat_|glpat-|sk-ant-|sk-proj-|sk-|rk_|pk_|xox[abposr]-|AIza|hf_|npm_|SG\.|AC)|[A-Za-z]{2,12}[_-])/);
  const prefix = prefixMatch ? prefixMatch[1] : s.slice(0, 4);
  const suffix = s.slice(-4);
  const hidden = Math.max(4, s.length - prefix.length - suffix.length);
  return `${prefix}${"•".repeat(Math.min(hidden, 24))}${suffix}`;
}

/**
 * Scans a string for credential material.
 *
 * @returns {Array<{detector:string,name:string,severity:string,start:number,end:number,length:number,masked:string,fingerprint:string,variable?:string}>}
 */
/**
 * Percent-decodes a string when doing so changes it.
 *
 * A credential in a query string is percent-encoded by construction:
 * `postgres://admin:pw@host/db` becomes `postgres%3A%2F%2Fadmin%3Apw%40host%2Fdb`,
 * and every detector that looks for `://` or `@` misses it. That is not an
 * exotic evasion — it is what `encodeURIComponent` does, so it happens by
 * accident on the way to happening on purpose.
 *
 * Decoded content is scanned in addition to the raw string, and offsets from
 * the decoded pass are discarded rather than mapped back: a decoded match means
 * the whole encoded run is the secret, so redaction targets that run.
 */
function decodeIfEncoded(value) {
  if (!/%[0-9a-f]{2}/i.test(value)) return null;
  try {
    const decoded = decodeURIComponent(value);
    return decoded === value ? null : decoded;
  } catch {
    return null;
  }
}

export function scanString(text, { detectors = DETECTORS } = {}) {
  const s = String(text ?? "");
  if (!s) return [];
  const subject = s.length > MAX_SCAN_BYTES ? s.slice(0, MAX_SCAN_BYTES) : s;

  const findings = [];
  const seen = new Set();

  // Second pass over the decoded form. Runs first so a decoded finding claims
  // its span before the raw pass produces a partial match inside it.
  const decoded = decodeIfEncoded(subject);
  if (decoded) {
    for (const finding of scanString(decoded, { detectors })) {
      // The encoded run in the ORIGINAL string is what gets masked and
      // redacted, so the offsets describe the text the caller actually holds.
      const encodedRun = subject.match(/[A-Za-z0-9%._~:/?#[\]@!$&'()*+,;=-]{16,}/);
      const start = encodedRun ? subject.indexOf(encodedRun[0]) : 0;
      const end = encodedRun ? start + encodedRun[0].length : subject.length;
      const key = `${start}:${end - start}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        ...finding,
        start,
        end,
        length: end - start,
        encoded: true,
        masked: mask(subject.slice(start, end)),
      });
    }
  }

  for (const detector of detectors) {
    // A fresh regex per scan: a shared /g regex carries `lastIndex` between
    // calls and silently skips every other match.
    const re = new RegExp(detector.pattern.source, detector.pattern.flags);
    let m;
    while ((m = re.exec(subject)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const group = detector.group ?? (m.length > 1 ? 1 : 0);
      const value = m[group] ?? m[0];
      if (!value) continue;
      if (detector.validate && !detector.validate(value)) continue;
      if (isPlaceholder(value) && detector.id !== "private-key") continue;

      // Offsets of the secret itself, not of the surrounding match, so
      // redaction replaces the credential and leaves `API_KEY=` readable.
      const offset = group === 0 ? m.index : subject.indexOf(value, m.index);
      const start = offset === -1 ? m.index : offset;

      // The same value found twice by two detectors is one leak.
      const key = `${start}:${value.length}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        detector: detector.id,
        name: detector.name,
        severity: detector.severity,
        start,
        end: start + value.length,
        length: value.length,
        masked: mask(value),
        fingerprint: fingerprint(value),
        ...(detector.nameGroup && m[detector.nameGroup]
          ? { variable: m[detector.nameGroup] }
          : {}),
      });
    }
  }

  return findings.sort((a, b) => a.start - b.start);
}

/**
 * Scans a JSON-shaped value, reporting the path to each finding.
 *
 * Paths are dotted with bracketed indices (`arguments.headers.authorization`,
 * `content[0].text`) so an operator can point at the exact field rather than
 * being told "somewhere in this payload".
 */
export function scan(value, { detectors = DETECTORS } = {}) {
  const findings = [];

  const walk = (node, path, depth) => {
    if (depth > MAX_DEPTH) return;
    if (typeof node === "string") {
      for (const f of scanString(node, { detectors })) findings.push({ ...f, path });
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, i) => walk(item, `${path}[${i}]`, depth + 1));
      return;
    }
    if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        walk(v, path ? `${path}.${k}` : k, depth + 1);
      }
    }
  };

  walk(value, "", 0);
  return findings;
}

/** True when anything at or above `floor` severity was found. */
export function hasSecrets(value, floor = SEVERITY.MEDIUM) {
  const rank = { [SEVERITY.MEDIUM]: 0, [SEVERITY.HIGH]: 1, [SEVERITY.CRITICAL]: 2 };
  return scan(value).some((f) => rank[f.severity] >= rank[floor]);
}

/* -------------------------------------------------------------------------- */
/*  Redaction                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Replaces every detected secret in a string.
 *
 * `replace` receives the finding and returns what goes in its place. The
 * default puts the masked shape back rather than a bare `[REDACTED]`, because
 * an agent that sees `AKIA••••••••••••EXMP` knows an AWS key was there and can
 * ask for a handle; one that sees `[REDACTED]` knows only that something was
 * taken away.
 *
 * Applied right-to-left so earlier offsets stay valid as the string changes
 * length underneath them.
 */
export function redactString(text, { detectors = DETECTORS, replace = (f) => f.masked } = {}) {
  const s = String(text ?? "");
  const findings = scanString(s, { detectors });
  if (!findings.length) return { text: s, findings };

  let out = s;
  for (const f of [...findings].sort((a, b) => b.start - a.start)) {
    out = out.slice(0, f.start) + replace(f) + out.slice(f.end);
  }
  return { text: out, findings };
}

/** `redactString` over a whole structure. */
export function redact(value, options = {}) {
  const findings = [];

  const walk = (node, path, depth) => {
    if (depth > MAX_DEPTH) return node;
    if (typeof node === "string") {
      const r = redactString(node, options);
      for (const f of r.findings) findings.push({ ...f, path });
      return r.text;
    }
    if (Array.isArray(node)) return node.map((item, i) => walk(item, `${path}[${i}]`, depth + 1));
    if (node && typeof node === "object") {
      return Object.fromEntries(
        Object.entries(node).map(([k, v]) => [k, walk(v, path ? `${path}.${k}` : k, depth + 1)]),
      );
    }
    return node;
  };

  return { value: walk(value, "", 0), findings };
}

/** Groups findings by detector for a summary line. */
export function summarize(findings) {
  const by = new Map();
  for (const f of findings) {
    const entry = by.get(f.detector) ?? { detector: f.detector, name: f.name, severity: f.severity, count: 0 };
    entry.count++;
    by.set(f.detector, entry);
  }
  return [...by.values()].sort((a, b) => b.count - a.count);
}
