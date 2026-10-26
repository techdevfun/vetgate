import { createHash } from "node:crypto";
import { get as httpsGet } from "node:https";
import { get as httpGet } from "node:http";
import { gunzipSync } from "node:zlib";

// Download helpers for the vet_package tool and the CLI. Nothing here
// executes anything: tarballs are gunzipped and parsed as a byte stream,
// script text is returned as a string. No child processes are spawned.

export interface FetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
}

function fetchBuffer(
  url: string,
  options: FetchOptions = {},
): Promise<Buffer> {
  const timeoutMs = options.timeoutMs ?? 10000;
  const maxBytes = options.maxBytes ?? 1_000_000;
  const maxRedirects = options.maxRedirects ?? 5;
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const getter = parsed.protocol === "https:" ? httpsGet : httpGet;
    const request = getter(
      url,
      { headers: { "User-Agent": "vetgate/0.1.0" } },
      (response) => {
        const status = response.statusCode ?? 0;
        if (status >= 300 && status < 400 && response.headers.location) {
          if (maxRedirects <= 0) {
            reject(new Error(`Too many redirects fetching ${url}`));
            return;
          }
          const next = new URL(response.headers.location, url).toString();
          response.resume();
          fetchBuffer(next, {
            timeoutMs,
            maxBytes,
            maxRedirects: maxRedirects - 1,
          }).then(resolve, reject);
          return;
        }
        if (status < 200 || status >= 300) {
          reject(new Error(`Fetch failed for ${url}: HTTP ${status}`));
          return;
        }
        const chunks: Buffer[] = [];
        let total = 0;
        response.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > maxBytes) {
            request.destroy(
              new Error(`Response exceeds the ${maxBytes} byte cap: ${url}`),
            );
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => resolve(Buffer.concat(chunks)));
        response.on("error", reject);
      },
    );
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error(`Fetch timed out after ${timeoutMs}ms: ${url}`));
    });
    request.on("error", reject);
  });
}

// Fetch a remote script text: 10 second timeout, 1MB cap, per the tool
// contract. The caller labels the fetch in the verdict manifest.
export async function fetchTextWithCap(url: string): Promise<string> {
  const buffer = await fetchBuffer(url, {
    timeoutMs: 10000,
    maxBytes: 1_000_000,
  });
  return buffer.toString("utf8");
}

export interface TarballResult {
  files: Record<string, string>;
  tarballSha256: string;
  tarballUrl: string;
}

function encodePackagePath(name: string): string {
  return name
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
}

// Minimal tar reader: enough for npm tarballs (ustar/pax). Extended
// headers (type "x"/"g") are skipped like any other non-file entry.
function extractTarball(gzipped: Buffer): Record<string, string> {
  let tar: Buffer;
  try {
    tar = gunzipSync(gzipped);
  } catch {
    throw new Error("Downloaded file is not a valid gzip tarball");
  }
  const files: Record<string, string> = {};
  let offset = 0;
  let totalBytes = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const rawName = header
      .subarray(0, 100)
      .toString("utf8")
      .replace(/\0.*$/, "");
    const sizeText = header
      .subarray(124, 136)
      .toString("utf8")
      .replace(/\0.*$/, "")
      .trim();
    const size = sizeText === "" ? 0 : parseInt(sizeText, 8);
    const typeFlag = String.fromCharCode(header[156]);
    const prefix = header
      .subarray(345, 500)
      .toString("utf8")
      .replace(/\0.*$/, "");
    const fullName = prefix ? `${prefix}/${rawName}` : rawName;
    const dataStart = offset + 512;
    const dataEnd = dataStart + (Number.isNaN(size) ? 0 : size);
    const isFile = typeFlag === "0" || typeFlag === "\0" || typeFlag === "";
    if (
      isFile &&
      fullName !== "" &&
      !fullName.startsWith("/") &&
      !fullName.split("/").includes("..")
    ) {
      const stripped = fullName.startsWith("package/")
        ? fullName.slice("package/".length)
        : fullName;
      if (stripped !== "") {
        totalBytes += size;
        if (totalBytes > 20_000_000) {
          throw new Error("Tarball contents exceed the 20MB extraction cap");
        }
        if (Object.keys(files).length >= 10000) {
          throw new Error("Tarball exceeds the 10000 file cap");
        }
        files[stripped] = tar.subarray(dataStart, dataEnd).toString("utf8");
      }
    }
    const blocks = Math.ceil((Number.isNaN(size) ? 0 : size) / 512);
    offset = dataStart + blocks * 512;
  }
  return files;
}

// Download an npm tarball, return its files plus the SHA-256 of the raw
// downloaded bytes. Never executes the contents.
export async function downloadNpmTarball(
  name: string,
  version: string,
): Promise<TarballResult> {
  const metadataUrl = `https://registry.npmjs.org/${encodePackagePath(name)}/${encodeURIComponent(version)}`;
  const metadataText = await fetchBuffer(metadataUrl, {
    timeoutMs: 30000,
    maxBytes: 10_000_000,
  }).then((buffer) => buffer.toString("utf8"));
  let metadata: unknown;
  try {
    metadata = JSON.parse(metadataText);
  } catch {
    throw new Error(`Registry metadata for ${name}@${version} is not JSON`);
  }
  const dist = (metadata as { dist?: { tarball?: string } }).dist;
  const tarballUrl = dist?.tarball;
  if (!tarballUrl) {
    throw new Error(`Registry metadata for ${name}@${version} has no tarball URL`);
  }
  const tarballBytes = await fetchBuffer(tarballUrl, {
    timeoutMs: 60000,
    maxBytes: 50_000_000,
  });
  const tarballSha256 = createHash("sha256").update(tarballBytes).digest("hex");
  const files = extractTarball(tarballBytes);
  return { files, tarballSha256, tarballUrl };
}
