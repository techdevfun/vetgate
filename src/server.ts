import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  vetAction,
  vetPackageContents,
  vetScriptContent,
} from "./vet.js";
import { downloadNpmTarball, fetchTextWithCap } from "./tarball.js";

function textResult(value: unknown): {
  content: { type: "text"; text: string }[];
} {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

export function createServer(): McpServer {
  const server = new McpServer({
    name: "vetgate",
    version: "0.1.0",
  });

  server.tool(
    "vet_package",
    "Vet an npm package BEFORE installing it. Downloads the published tarball, inspects its manifest, install scripts, and scanned file contents, and returns a deterministic verdict (ALLOW, DENY, or REVIEW) with the exact evidence string for every finding. The package is never executed and no install script is run. Only the npm ecosystem is supported in v1; other ecosystems are rejected with a clear error. The verdict artifact sha256 is the SHA-256 of the downloaded tarball bytes.",
    {
      ecosystem: z
        .string()
        .describe('Package ecosystem. Only "npm" is supported in v1.'),
      name: z.string().describe("Package name, for example react."),
      version: z.string().describe("Exact version, for example 18.3.1."),
    },
    async ({ ecosystem, name, version }) => {
      if (ecosystem !== "npm") {
        throw new Error(
          `Unsupported ecosystem: ${ecosystem}. vetgate v1 supports npm only.`,
        );
      }
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
      // The registry artifact hash is the verifiable one for a downloaded
      // package; the content hash is documented on vetPackageContents.
      verdict.artifact.sha256 = tarball.tarballSha256;
      return textResult(verdict);
    },
  );

  server.tool(
    "vet_action",
    "Vet a GitHub Action ref BEFORE using it. This is a local form check only: a full 40-hex commit SHA returns ALLOW, a mutable tag such as v4 or main returns REVIEW with a pin-to-digest recommendation, and :latest, untagged, or malformed refs return DENY. No network call is made.",
    {
      ref: z
        .string()
        .describe("Action ref, for example actions/checkout@v4."),
    },
    async ({ ref }) => {
      return textResult(vetAction(ref));
    },
  );

  server.tool(
    "vet_script",
    "Vet a remote script BEFORE running it. Fetches the script text (10 second timeout, 1MB cap), scans it for download-and-execute chains, credential-plus-network exfiltration, obfuscation combined with network calls, and hidden unicode tricks, and returns a deterministic verdict. The script is never executed. Note: fetching the script text is itself a network fetch, which is labeled in the verdict manifest; all analysis is local.",
    {
      url: z.string().describe("URL of the script to fetch and vet."),
    },
    async ({ url }) => {
      const text = await fetchTextWithCap(url);
      return textResult(vetScriptContent({ url, text }));
    },
  );

  return server;
}

export async function runServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

async function main(): Promise<void> {
  await runServer();
}

// Run as a stdio MCP server when executed directly (not when imported).
const invokedPath = process.argv[1] ?? "";
if (invokedPath.endsWith("server.js") || invokedPath.endsWith("server.ts")) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
