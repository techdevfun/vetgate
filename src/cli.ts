#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { vetAction, vetPackageContents, vetScriptContent } from "./vet.js";
import type { Verdict } from "./vet.js";
import { downloadNpmTarball, fetchTextWithCap } from "./tarball.js";

const USAGE = `vetgate check <spec> | serve
Specs:
  npm:name@version        Vet an npm package (downloads its tarball, never executes it)
  action:owner/repo@ref    Vet a GitHub Action ref (local form check only)
  url:https://...          Vet a remote script (fetches text, never executes it)
  local:<dir>              Fixture mode: vet a local directory as a package
                           (reads package.json plus files; for offline fixtures
                           and demos, not a shipped MCP feature)
serve runs the MCP server over stdio.
Output: Verdict JSON on stdout. Exit 0 on ALLOW, exit 1 on DENY or REVIEW,
plus one summary line on stderr.
`;

function readLocalDirectory(dir: string): {
  packageJson: unknown;
  files: Record<string, string>;
} {
  const root = resolve(dir);
  const files: Record<string, string> = {};
  const walk = (current: string, prefix: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const full = join(current, entry.name);
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        walk(full, rel);
      } else if (entry.isFile()) {
        const size = statSync(full).size;
        if (size > 1_000_000) continue;
        files[rel] = readFileSync(full, "utf8");
      }
    }
  };
  walk(root, "");
  let packageJson: unknown = {};
  const packageJsonText = files["package.json"];
  if (packageJsonText) {
    try {
      packageJson = JSON.parse(packageJsonText);
    } catch {
      packageJson = {};
    }
  }
  return { packageJson, files };
}

function splitNpmSpec(spec: string): { name: string; version: string } {
  const atIndex = spec.lastIndexOf("@");
  if (atIndex <= 0) {
    throw new Error(
      `npm spec needs name@version, got: ${spec} (example: npm:react@18.3.1)`,
    );
  }
  return {
    name: spec.slice(0, atIndex),
    version: spec.slice(atIndex + 1),
  };
}

async function checkSpec(spec: string): Promise<Verdict> {
  if (spec.startsWith("npm:")) {
    const { name, version } = splitNpmSpec(spec.slice("npm:".length));
    const tarball = await downloadNpmTarball(name, version);
    let packageJson: unknown = {};
    const packageJsonText = tarball.files["package.json"];
    if (packageJsonText) {
      try {
        packageJson = JSON.parse(packageJsonText);
      } catch {
        packageJson = {};
      }
    }
    const verdict = vetPackageContents({
      name,
      version,
      packageJson,
      files: tarball.files,
    });
    verdict.artifact.sha256 = tarball.tarballSha256;
    return verdict;
  }
  if (spec.startsWith("action:")) {
    return vetAction(spec.slice("action:".length));
  }
  if (spec.startsWith("url:")) {
    const url = spec.slice("url:".length);
    const text = await fetchTextWithCap(url);
    return vetScriptContent({ url, text });
  }
  if (spec.startsWith("local:")) {
    const dir = spec.slice("local:".length);
    const { packageJson, files } = readLocalDirectory(dir);
    const parsed = packageJson as Record<string, unknown>;
    const name =
      typeof parsed["name"] === "string" ? parsed["name"] : "unknown";
    const version =
      typeof parsed["version"] === "string" ? parsed["version"] : "0.0.0";
    return vetPackageContents({ name, version, packageJson, files });
  }
  throw new Error(`Unknown spec: ${spec}\n${USAGE}`);
}

async function main(): Promise<void> {
  const [command, spec] = process.argv.slice(2);
  if (command === "serve") {
    const { runServer } = await import("./server.js");
    await runServer();
    return;
  }
  if (command !== "check" || !spec) {
    process.stdout.write(USAGE);
    process.exit(1);
  }
  const verdict = await checkSpec(spec);
  process.stdout.write(JSON.stringify(verdict, null, 2) + "\n");
  process.stderr.write(
    `vetgate: ${verdict.verdict} — ${verdict.findings.length} finding(s)\n`,
  );
  process.exit(verdict.verdict === "ALLOW" ? 0 : 1);
}

main().catch((error: unknown) => {
  process.stderr.write(
    (error instanceof Error ? error.message : String(error)) + "\n",
  );
  process.exit(1);
});
