import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const cli = join(root, "dist", "cli.js");

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
  });
}

test("CLI local: benign fixture exits 0 with ALLOW", () => {
  const result = run(["check", "local:tests/fixtures/benign"]);
  assert.equal(result.status, 0, result.stderr);
  const verdict = JSON.parse(result.stdout);
  assert.equal(verdict.verdict, "ALLOW");
  assert.match(result.stderr, /^vetgate: ALLOW — 0 finding\(s\)\n$/);
});

test("CLI local: exfil fixture exits 1 with DENY", () => {
  const result = run(["check", "local:tests/fixtures/exfil"]);
  assert.equal(result.status, 1);
  const verdict = JSON.parse(result.stdout);
  assert.equal(verdict.verdict, "DENY");
  assert.ok(verdict.findings.some((f) => f.rule === "install-script-exfil"));
  assert.match(result.stderr, /^vetgate: DENY — \d+ finding\(s\)\n$/);
});

test("CLI action: SHA exits 0, mutable tag exits 1 with REVIEW", () => {
  const clean = run([
    "check",
    "action:actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
  ]);
  assert.equal(clean.status, 0, clean.stderr);
  assert.equal(JSON.parse(clean.stdout).verdict, "ALLOW");

  const mutable = run(["check", "action:actions/checkout@v4"]);
  assert.equal(mutable.status, 1);
  const verdict = JSON.parse(mutable.stdout);
  assert.equal(verdict.verdict, "REVIEW");
  assert.ok(verdict.findings.some((f) => f.rule === "action-mutable-tag"));
});
