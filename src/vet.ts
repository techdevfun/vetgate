import { createHash } from "node:crypto";

// vetgate core: pure, offline, deterministic rule engine.
// No network, no execution, no model calls. Every rule below is also
// documented in docs/RULES.md with the fixture that triggers it.

export type VerdictKind = "ALLOW" | "DENY" | "REVIEW";
export type Severity = "high" | "medium" | "low";

export interface Finding {
  rule: string;
  severity: Severity;
  evidence: string;
  signal: "local";
}

export interface Verdict {
  verdict: VerdictKind;
  artifact: {
    kind: string;
    name: string;
    version: string | null;
    sha256: string | null;
  };
  findings: Finding[];
  manifest: {
    rulesVersion: string;
    checkedAt: string;
    signals: string[];
    note?: string;
  };
  safeAction: string | null;
}

export const RULES_VERSION = "2026.10";

// Popular package names used by the typosquat rule. This list is a fixed,
// documented sample of well-known npm packages. It is NOT exhaustive, and
// vetgate never claims it is: a name absent from this list is simply not
// checked for typosquatting, never declared safe because of that absence.
export const POPULAR_PACKAGES: readonly string[] = [
  "react",
  "react-dom",
  "lodash",
  "express",
  "axios",
  "typescript",
  "eslint",
  "prettier",
  "vite",
  "webpack",
  "jest",
  "vitest",
  "commander",
  "chalk",
  "next",
  "vue",
  "angular",
  "svelte",
  "node-fetch",
  "request",
  "moment",
  "dayjs",
  "uuid",
  "dotenv",
  "cors",
  "mongoose",
  "prisma",
  "tailwindcss",
  "babel",
  "rollup",
  "esbuild",
  "nodemon",
  "pm2",
  "socket.io",
  "graphql",
  "apollo",
  "fastify",
  "koa",
  "nestjs",
];

// Install-script keys inspected in package.json.
const INSTALL_SCRIPT_KEYS = ["preinstall", "install", "postinstall", "prepare"];

// Credential / environment-read patterns. A match here is only half of an
// exfiltration finding: the same text must also match a network-send
// pattern before any DENY is produced.
const CREDENTIAL_PATTERNS: RegExp[] = [
  /process\.env(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])/,
  /\$ENV\b/,
  /\/etc\/passwd/,
  /\.npmrc/,
  /\.aws\/credentials/,
  /\b[A-Z][A-Z0-9_]*TOKEN\b/,
  /\bAWS_SECRET_ACCESS_KEY\b/,
];

// Network-send patterns: an actual send primitive or an outbound URL.
const NETWORK_SEND_PATTERNS: RegExp[] = [
  /\bfetch\s*\(/,
  /\bcurl\b/,
  /\bwget\b/,
  /\bXMLHttpRequest\b/,
  /https?\.request\s*\(/,
  /\bnet\.connect\s*\(/,
  /\bsocket\.connect\s*\(/,
];

const OUTBOUND_URL_PATTERN = /https?:\/\/[^\s'"`)]+/;

// Download-and-execute chains.
const DOWNLOAD_EXECUTE_PATTERNS: RegExp[] = [
  /(?:\bcurl\b|\bwget\b)[^|\n\r]*\|\s*(?:sh|bash|node)\b/,
  /powershell\b[^;\n\r]*\bIEX\b[^;\n\r]*https?:\/\//i,
  /powershell\b[^;\n\r]*https?:\/\/[^;\n\r]*\bIEX\b/i,
];

// Obfuscation markers. Each is DENY only when combined with a network
// call in the same text (rule obfuscated-network).
const OBFUSCATION_PATTERNS: RegExp[] = [
  /eval\s*\(\s*atob\s*\(/,
  // Buffer.from(x, "base64") followed later by eval(.
  /Buffer\.from\s*\([^)]*['"]base64['"]\s*\)[\s\S]{0,500}?eval\s*\(/,
  // String.fromCharCode with 10 or more arguments.
  /String\.fromCharCode\s*\((?:[^()]*,){9,}[^()]*\)/,
  // Dense hex escapes: 8 or more \xNN sequences in one run.
  /(?:\\x[0-9a-fA-F]{2}){8,}/,
];

// Zero-width and bidirectional-override characters.
const HIDDEN_UNICODE_PATTERN =
  /[\u200B\u200C\u200D\u2066\u2067\u2068\u2069\uFEFF\u202A\u202B\u202C\u202D\u202E]/;

const MAX_EVIDENCE_CHARS = 120;

function truncate(text: string): string {
  return text.length <= MAX_EVIDENCE_CHARS
    ? text
    : text.slice(0, MAX_EVIDENCE_CHARS);
}

function firstMatch(text: string, patterns: RegExp[]): RegExpExecArray | null {
  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match) return match;
  }
  return null;
}

function hasMatch(text: string, patterns: RegExp[]): boolean {
  return firstMatch(text, patterns) !== null;
}

function hasNetworkSend(text: string): boolean {
  return (
    hasMatch(text, NETWORK_SEND_PATTERNS) ||
    OUTBOUND_URL_PATTERN.test(text)
  );
}

function hasHiddenUnicode(text: string): boolean {
  return HIDDEN_UNICODE_PATTERN.test(text);
}

function hiddenUnicodeEvidence(text: string): string {
  const match = HIDDEN_UNICODE_PATTERN.exec(text);
  if (!match || match.index === undefined) return "hidden unicode character";
  const start = Math.max(0, match.index - 40);
  return truncate(text.slice(start, match.index + 40));
}

function windowEvidence(text: string, index: number): string {
  const start = Math.max(0, index - 20);
  return truncate(text.slice(start));
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const prev: number[] = [];
  const curr: number[] = [];
  for (let j = 0; j <= b.length; j++) prev.push(j);
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= b.length; j++) prev[j] = curr[j];
  }
  return prev[b.length];
}

function makeFinding(
  rule: string,
  severity: Severity,
  evidence: string,
): Finding {
  return { rule, severity, evidence: truncate(evidence), signal: "local" };
}

function assemble(
  artifact: Verdict["artifact"],
  findings: Finding[],
  safeActionFor: (findings: Finding[]) => string | null,
  note?: string,
): Verdict {
  const hasDeny = findings.some((f) => f.severity === "high");
  const hasReview = findings.length > 0;
  const verdict: VerdictKind = hasDeny
    ? "DENY"
    : hasReview
      ? "REVIEW"
      : "ALLOW";
  const manifest: Verdict["manifest"] = {
    rulesVersion: RULES_VERSION,
    checkedAt: new Date().toISOString(),
    signals: ["local"],
  };
  if (note) manifest.note = note;
  return {
    verdict,
    artifact,
    findings,
    manifest,
    safeAction: verdict === "ALLOW" ? null : safeActionFor(findings),
  };
}

// Scan one script-like text for the DENY/REVIEW findings that apply to it.
// exfilRule is the rule id used for the credential-plus-network finding so
// each surface (install script, scanned file, remote script) keeps its own
// id while sharing the same logic.
function scanScriptText(
  text: string,
  exfilRule: string,
  downloadRule = "download-execute",
  obfuscationRule = "obfuscated-network",
): Finding[] {
  const findings: Finding[] = [];
  const cred = firstMatch(text, CREDENTIAL_PATTERNS);
  const net = firstMatch(text, NETWORK_SEND_PATTERNS);
  const url = OUTBOUND_URL_PATTERN.exec(text);
  const hasNet = net !== null || url !== null;

  const dl = firstMatch(text, DOWNLOAD_EXECUTE_PATTERNS);
  if (dl && dl.index !== undefined) {
    findings.push(
      makeFinding(downloadRule, "high", windowEvidence(text, dl.index)),
    );
  }

  if (cred && cred.index !== undefined && hasNet) {
    findings.push(
      makeFinding(exfilRule, "high", windowEvidence(text, cred.index)),
    );
  }

  const obf = firstMatch(text, OBFUSCATION_PATTERNS);
  if (obf && obf.index !== undefined && hasNet) {
    findings.push(
      makeFinding(obfuscationRule, "high", windowEvidence(text, obf.index)),
    );
  }

  const hidden = hasHiddenUnicode(text);
  if (hidden && hasNet) {
    findings.push(
      makeFinding("hidden-unicode-network", "high", hiddenUnicodeEvidence(text)),
    );
  } else if (hidden) {
    findings.push(
      makeFinding("hidden-unicode", "medium", hiddenUnicodeEvidence(text)),
    );
  }

  return findings;
}

export interface PackageContentsInput {
  name: string;
  version: string;
  packageJson: unknown;
  files: Record<string, string>;
}

function parsePackageJson(input: unknown): Record<string, unknown> {
  if (typeof input === "string") {
    try {
      const parsed: unknown = JSON.parse(input);
      return typeof parsed === "object" && parsed !== null
        ? (parsed as Record<string, unknown>)
        : {};
    } catch {
      return {};
    }
  }
  if (typeof input === "object" && input !== null) {
    return input as Record<string, unknown>;
  }
  return {};
}

// sha256 of the concatenated file contents, files ordered by sorted
// filename, with no separators and no filenames mixed in. This is the
// content hash for the direct-contents API; the MCP vet_package tool
// replaces artifact.sha256 with the downloaded tarball SHA-256 (see
// src/tarball.ts), which is the verifiable registry artifact hash.
export function hashPackageContents(files: Record<string, string>): string {
  const sorted = Object.keys(files).sort();
  const joined = sorted.map((key) => files[key]).join("");
  return createHash("sha256").update(joined, "utf8").digest("hex");
}

export function vetPackageContents(
  input: PackageContentsInput,
): Verdict {
  const { name, version } = input;
  const files = input.files ?? {};
  const pkg = parsePackageJson(input.packageJson);
  const findings: Finding[] = [];

  // Typosquat: Levenshtein distance exactly 1 from a popular package name.
  // An exact popular name (distance 0) is never a typosquat finding.
  // Scoped names (starting with @) are not checked against bare names.
  if (!name.startsWith("@") && !POPULAR_PACKAGES.includes(name)) {
    for (const popular of POPULAR_PACKAGES) {
      if (levenshtein(name, popular) === 1) {
        findings.push(
          makeFinding(
            "typosquat",
            "high",
            `package name "${name}" is 1 edit away from popular package "${popular}"`,
          ),
        );
        break;
      }
    }
  }

  // Install scripts from package.json.
  const scriptsRaw = pkg["scripts"];
  const scripts: Record<string, unknown> =
    typeof scriptsRaw === "object" && scriptsRaw !== null
      ? (scriptsRaw as Record<string, unknown>)
      : {};
  for (const key of INSTALL_SCRIPT_KEYS) {
    const script = scripts[key];
    if (typeof script !== "string" || script === "") continue;
    findings.push(...scanScriptText(script, "install-script-exfil"));
    findings.push(
      makeFinding(
        "install-script-present",
        "medium",
        `${key}: ${script}`,
      ),
    );
  }

  // Scanned .js / .sh file contents passed in files.
  for (const filename of Object.keys(files).sort()) {
    if (!filename.endsWith(".js") && !filename.endsWith(".sh")) continue;
    findings.push(...scanScriptText(files[filename], "file-exfil"));
  }

  // Missing license field: REVIEW only, never DENY.
  const license = pkg["license"];
  const licenseMissing =
    license === undefined ||
    license === null ||
    (typeof license === "string" && license.trim() === "");
  if (licenseMissing) {
    findings.push(
      makeFinding(
        "missing-license",
        "low",
        `package.json: no "license" field for package "${name}"`,
      ),
    );
  }

  return assemble(
    {
      kind: "npm-package",
      name,
      version,
      sha256: hashPackageContents(files),
    },
    findings,
    (list) => {
      if (list.some((f) => f.severity === "high")) {
        return "Do not install this package. If you must inspect it, download it with scripts disabled and read the flagged code first.";
      }
      if (list.some((f) => f.rule === "install-script-present")) {
        return "Install with --ignore-scripts, then run the build step manually if you trust the code after reading it.";
      }
      return "Ask the user whether this package is acceptable for this use.";
    },
  );
}

export function vetAction(ref: string): Verdict {
  const findings: Finding[] = [];
  let artifactName = ref;
  let artifactVersion: string | null = null;

  const fail = (rule: string, evidence: string): Verdict =>
    assemble(
      { kind: "github-action", name: artifactName, version: artifactVersion, sha256: null },
      [makeFinding(rule, "high", evidence)],
      () => "Do not use this action ref.",
    );

  if (ref.trim() !== ref || ref.includes(" ") || ref.includes("\t")) {
    return fail("action-unpinned", ref === "" ? "(empty ref)" : ref);
  }
  if (ref === "") {
    return fail("action-unpinned", "(empty ref)");
  }
  const atIndex = ref.lastIndexOf("@");
  if (atIndex === -1) {
    return fail("action-unpinned", ref);
  }
  const ownerRepo = ref.slice(0, atIndex);
  const refPart = ref.slice(atIndex + 1);
  artifactName = ownerRepo;
  artifactVersion = refPart === "" ? null : refPart;

  if (!/^[^/\s]+\/[^/\s]+$/.test(ownerRepo)) {
    return fail("action-unpinned", ref);
  }
  if (refPart === "" || refPart === "latest" || refPart.startsWith(":")) {
    return fail("action-unpinned", refPart === "" ? ref : refPart);
  }
  if (/^[0-9a-f]{40}$/i.test(refPart)) {
    return assemble(
      { kind: "github-action", name: ownerRepo, version: refPart, sha256: null },
      [],
      () => null,
    );
  }
  // Any other ref is a mutable tag (v4, main, a semver tag): REVIEW.
  return assemble(
    { kind: "github-action", name: ownerRepo, version: refPart, sha256: null },
    [
      makeFinding(
        "action-mutable-tag",
        "medium",
        `action ref "${refPart}" is a mutable tag, not a pinned commit SHA`,
      ),
    ],
    () =>
      "Pin the action to a full commit SHA (digest) instead of the mutable tag.",
  );
}

export interface ScriptContentInput {
  url: string;
  text: string;
}

const SCRIPT_NOTE =
  "The script text itself was fetched over the network to perform this check; all analysis was local and the script was never executed.";

export function vetScriptContent(input: ScriptContentInput): Verdict {
  const { url, text } = input;
  const findings = scanScriptText(text, "script-exfil");
  // Outbound URL with no DENY pattern: REVIEW, never DENY on its own.
  const hasDeny = findings.some((f) => f.severity === "high");
  const urlMatch = OUTBOUND_URL_PATTERN.exec(text);
  if (!hasDeny && urlMatch) {
    findings.push(
      makeFinding(
        "outbound-url",
        "medium",
        windowEvidence(text, urlMatch.index ?? 0),
      ),
    );
  }
  return assemble(
    { kind: "remote-script", name: url, version: null, sha256: null },
    findings,
    (list) => {
      if (list.some((f) => f.severity === "high")) {
        return "Do not run this script.";
      }
      if (list.some((f) => f.rule === "outbound-url" || f.rule === "hidden-unicode")) {
        return "Ask the user before running this script; do not execute it automatically.";
      }
      return "Do not run this script.";
    },
    SCRIPT_NOTE,
  );
}
