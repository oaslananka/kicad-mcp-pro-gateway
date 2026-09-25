import { chmodSync, copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "../../..");

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 && index + 1 < process.argv.length ? process.argv[index + 1] : fallback;
}

const profile = option("--profile", "debug");
const cargoProfile = profile === "debug" ? "dev" : profile;
if (profile !== "debug" && profile !== "release") {
  throw new Error(`unsupported Rust profile: ${profile}`);
}

function commandOutput(command, args) {
  const result = spawnSync(command, args, { cwd: repositoryRoot, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.stderr.trim()}`);
  }
  return result.stdout.trim();
}

function cargoPackageVersion(manifestPath, packageName) {
  const metadata = JSON.parse(
    commandOutput("cargo", [
      "metadata",
      "--format-version",
      "1",
      "--no-deps",
      "--manifest-path",
      manifestPath,
    ]),
  );
  const packageMetadata = metadata.packages.find(
    (candidate) => candidate.name === packageName,
  );
  if (!packageMetadata) {
    throw new Error(`Cargo package ${packageName} was not found in metadata`);
  }
  return packageMetadata.version;
}

function verifyReleaseVersions() {
  const daemonVersion = cargoPackageVersion(
    "apps/daemon/Cargo.toml",
    "kicad-mcp-gateway-daemon",
  );
  const desktopVersion = cargoPackageVersion(
    "apps/desktop/src-tauri/Cargo.toml",
    "kicad-mcp-gateway-desktop",
  );
  const tauriConfig = JSON.parse(
    readFileSync(join(repositoryRoot, "apps/desktop/src-tauri/tauri.conf.json"), "utf8"),
  );
  if (desktopVersion !== daemonVersion || tauriConfig.version !== daemonVersion) {
    throw new Error(
      `Gateway lifecycle version mismatch: daemon=${daemonVersion}, desktop=${desktopVersion}, tauri=${tauriConfig.version}`,
    );
  }
}

verifyReleaseVersions();

const target = option(
  "--target",
  process.env.TAURI_BUILD_TARGET || commandOutput("rustc", ["--print", "host-tuple"]),
);
const executableSuffix = target.includes("windows") ? ".exe" : "";
const executableName = `kicad-mcp-gateway-daemon${executableSuffix}`;
const builtBinary = join(
  repositoryRoot,
  "target",
  target,
  profile,
  executableName,
);
const sidecarDirectory = join(repositoryRoot, "apps", "desktop", "src-tauri", "bin");
const stagedSidecar = join(sidecarDirectory, `kicad-mcp-gateway-daemon-${target}${executableSuffix}`);

const cargo = spawnSync(
  "cargo",
  [
    "build",
    "--locked",
    "--manifest-path",
    "apps/daemon/Cargo.toml",
    "--package",
    "kicad-mcp-gateway-daemon",
    "--target",
    target,
    "--profile",
    cargoProfile,
  ],
  { cwd: repositoryRoot, stdio: "inherit" },
);
if (cargo.status !== 0) {
  process.exit(cargo.status ?? 1);
}

mkdirSync(sidecarDirectory, { recursive: true });
copyFileSync(builtBinary, stagedSidecar);
if (process.platform !== "win32") {
  chmodSync(stagedSidecar, 0o755);
}
console.log(`staged packaged daemon sidecar: ${stagedSidecar}`);
