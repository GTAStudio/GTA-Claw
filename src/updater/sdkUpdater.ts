import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { logger } from "../utils/logger.js";
import { fetch } from "../utils/proxy.js";

const execFileAsync = promisify(execFile);

interface VersionInfo {
  sdk: { installed: string; latest: string; updateAvailable: boolean };
  cli: { installed: string; latest: string; updateAvailable: boolean };
}

// @github/copilot-sdk's own default CLI resolution (getBundledCliPath(),
// unchanged in behavior from 0.1.x through at least 1.0.8) always resolves to
// a *.js entrypoint (the platform package's "./sdk" export, transformed into
// "<package>/index.js") and always spawns it via
// `spawn(process.execPath, [cliPath, ...args])` -- i.e. re-executed under
// *this host's* installed Node.js binary. That JS bundle (confirmed
// empirically against @github/copilot-win32-x64@1.0.75 and
// @github/copilot-linux-x64@1.0.75, which ship byte-identical index.js/app.js
// entrypoints) requires `Promise.withResolvers`, which only exists on
// Node.js >=22. This legacy image's Node runtime is pinned to the node:20
// base image, so spawning the SDK's default JS entrypoint fails outright
// (verified: `node index.js --version` throws
// "TypeError: Promise.withResolvers is not a function" before printing
// anything).
//
// Each @github/copilot-<platform>-<arch> package also exposes a "." export
// pointing at a precompiled, self-contained native binary (a Node.js Single
// Executable Application with its own embedded >=22 runtime -- confirmed via
// `node:sea` usage in the bundle and by directly invoking
// @github/copilot-win32-x64's copilot.exe, which runs correctly regardless of
// the host's installed Node version). CopilotClient's own spawn logic
// (client.js's `isJsFile` branch) already treats a non-".js" cliPath as a
// directly-executable binary and spawns it as-is, passing the exact same CLI
// arguments either way -- this is a first-class supported code path, not a
// workaround. Resolving to that native binary instead of the SDK's default
// JS entrypoint is therefore the correct fix for a Node 20 host: it sidesteps
// the host/bundle Node-version mismatch entirely instead of requiring a
// Node 22+ base image.
//
// This lives here (rather than its own module) so the legacy TypeScript
// surface's tracked file count does not grow; both this module and
// engine/copilotEngine.ts need it, so it is exported for reuse.
export function resolveBundledCliPath(): string {
  const arch = process.arch;
  const platformCandidates =
    process.platform === "linux" ? ["linux", "linuxmusl"] : [process.platform];

  for (const platform of platformCandidates) {
    try {
      const cliUrl = import.meta.resolve(
        `@github/copilot-${platform}-${arch}`,
      );
      return fileURLToPath(cliUrl);
    } catch {
      // Not installed for this platform/arch (e.g. glibc vs musl on Linux) —
      // try the next candidate.
    }
  }

  throw new Error(
    `Could not resolve a @github/copilot-<platform>-<arch> package for ` +
      `${process.platform}/${arch}. Ensure the matching platform package is ` +
      "installed, or pass an explicit cliPath to CopilotClient.",
  );
}

async function getInstalledSdkVersion(): Promise<string> {
  try {
    const pkgPath = new URL(
      "../../node_modules/@github/copilot-sdk/package.json",
      import.meta.url,
    );
    const raw = await readFile(pkgPath, "utf-8");
    const pkg = JSON.parse(raw) as { version: string };
    return pkg.version;
  } catch {
    return "unknown";
  }
}

async function getLatestSdkVersion(): Promise<string> {
  try {
    const resp = await fetch(
      "https://registry.npmjs.org/@github/copilot-sdk/latest",
      { signal: AbortSignal.timeout(10_000) },
    );
    if (!resp.ok) return "unknown";
    const data = (await resp.json()) as { version: string };
    return data.version;
  } catch {
    return "unknown";
  }
}

async function getInstalledCliVersion(): Promise<string> {
  try {
    // resolveBundledCliPath() (above) returns the platform package's native
    // binary, so it must be spawned directly rather than wrapped as
    // `node <cliPath>`.
    const cliPath = resolveBundledCliPath();
    const { stdout } = await execFileAsync(cliPath, ["--version"], {
      timeout: 5000,
    });
    // The binary prints a full sentence (e.g. "GitHub Copilot CLI 1.0.75.\n
    // Run 'copilot update' to check for updates."), not a bare version —
    // extract just the semver so it compares cleanly against the registry's
    // "latest" version instead of always looking stale.
    const match = stdout.match(/(\d+\.\d+\.\d+)/);
    return match ? match[1] : stdout.trim();
  } catch {
    return "unknown";
  }
}

async function getLatestCliVersion(): Promise<string> {
  try {
    const resp = await fetch(
      "https://api.github.com/repos/github/copilot-cli/releases/latest",
      {
        signal: AbortSignal.timeout(10_000),
        headers: { Accept: "application/vnd.github+json" },
      },
    );
    if (!resp.ok) return "unknown";
    const data = (await resp.json()) as { tag_name: string };
    return data.tag_name.replace(/^v/, "");
  } catch {
    return "unknown";
  }
}

// autoUpdate is accepted for config-surface compatibility (AUTO_UPDATE env
// var) but is report-only: the running container must never rewrite its own
// dependency graph (`npm update`) or re-run an installer script
// (`curl | bash`) against itself. Updates are applied by rebuilding and
// redeploying the image, not by live self-mutation.
export async function checkForUpdates(autoUpdate = false): Promise<VersionInfo> {
  logger.info("Checking for SDK/CLI updates...");

  const [sdkInstalled, sdkLatest, cliInstalled, cliLatest] = await Promise.all([
    getInstalledSdkVersion(),
    getLatestSdkVersion(),
    getInstalledCliVersion(),
    getLatestCliVersion(),
  ]);

  const info: VersionInfo = {
    sdk: {
      installed: sdkInstalled,
      latest: sdkLatest,
      updateAvailable:
        sdkInstalled !== "unknown" &&
        sdkLatest !== "unknown" &&
        sdkInstalled !== sdkLatest,
    },
    cli: {
      installed: cliInstalled,
      latest: cliLatest,
      updateAvailable:
        cliInstalled !== "unknown" &&
        cliLatest !== "unknown" &&
        cliInstalled !== cliLatest,
    },
  };

  logger.info(
    {
      sdk: `${info.sdk.installed} → ${info.sdk.latest}`,
      cli: `${info.cli.installed} → ${info.cli.latest}`,
    },
    "Version check complete",
  );

  if (info.sdk.updateAvailable) {
    logger.warn(
      { installed: sdkInstalled, latest: sdkLatest },
      "SDK update available (rebuild the image to apply)",
    );
  }
  if (info.cli.updateAvailable) {
    logger.warn(
      { installed: cliInstalled, latest: cliLatest },
      "CLI update available (rebuild the image to apply)",
    );
  }

  if (autoUpdate && (info.sdk.updateAvailable || info.cli.updateAvailable)) {
    logger.warn(
      "AUTO_UPDATE is set, but live self-mutation (npm update / curl | bash) " +
        "has been removed for security. This check is report-only — rebuild " +
        "and redeploy the image to apply the update(s) above.",
    );
  }

  return info;
}
