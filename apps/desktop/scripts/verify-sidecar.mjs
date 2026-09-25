import { existsSync, readdirSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";

const target = process.env.TAURI_BUILD_TARGET;
const defaultReleasePath = join(
  "src-tauri",
  "target",
  ...(target ? [target] : []),
  "release",
);
const releaseDirectory = resolve(process.argv[2] ?? defaultReleasePath);
const bundleDirectory = join(releaseDirectory, "bundle");
if (!existsSync(releaseDirectory)) {
  throw new Error(`Tauri release directory does not exist: ${releaseDirectory}`);
}
if (!existsSync(bundleDirectory)) {
  throw new Error(`Tauri bundle directory does not exist: ${bundleDirectory}`);
}
const expectedNames = new Set([
  "kicad-mcp-gateway-daemon",
  "kicad-mcp-gateway-daemon.exe",
]);

const matches = [];
function visit(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      visit(path);
    } else if (entry.isFile() && expectedNames.has(basename(path))) {
      matches.push(path);
    }
  }
}
visit(releaseDirectory);

if (matches.length === 0) {
  throw new Error(`no packaged Gateway daemon sidecar found under ${releaseDirectory}`);
}
for (const path of matches) {
  const metadata = statSync(path);
  if (metadata.size === 0) {
    throw new Error(`packaged Gateway daemon sidecar is empty: ${path}`);
  }
  if (process.platform !== "win32" && (metadata.mode & 0o111) === 0) {
    throw new Error(`packaged Gateway daemon sidecar is not executable: ${path}`);
  }
}
console.log(`verified packaged Gateway daemon sidecar: ${matches.join(", ")}`);
