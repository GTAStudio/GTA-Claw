import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { logger } from "../utils/logger.js";
import { fetch } from "../utils/proxy.js";

const execFileAsync = promisify(execFile);

interface VersionInfo {
  sdk: { installed: string; latest: string; updateAvailable: boolean };
  cli: { installed: string; latest: string; updateAvailable: boolean };
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
    const cliPath =
      process.env["COPILOT_CLI_PATH"] ??
      (process.platform === "win32" ? "copilot.cmd" : "copilot");
    const { stdout } = await execFileAsync(cliPath, ["--version"], {
      timeout: 5000,
    });
    return stdout.trim();
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
      "SDK update available",
    );
  }
  if (info.cli.updateAvailable) {
    logger.warn(
      { installed: cliInstalled, latest: cliLatest },
      "CLI update available",
    );
  }

  // Auto-update if enabled
  if (autoUpdate) {
    if (info.sdk.updateAvailable) {
      await performSdkUpdate();
    }
    if (info.cli.updateAvailable) {
      await performCliUpdate();
    }
  }

  return info;
}

async function performSdkUpdate(): Promise<void> {
  logger.info("Auto-updating @github/copilot-sdk...");
  try {
    const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
    await execFileAsync(npmCmd, ["update", "@github/copilot-sdk"], {
      timeout: 120_000,
    });
    logger.info("SDK updated successfully");
  } catch (err) {
    logger.error({ err }, "SDK auto-update failed");
  }
}

async function performCliUpdate(): Promise<void> {
  logger.info("Auto-updating Copilot CLI...");
  if (process.platform === "win32") {
    logger.warn(
      "CLI auto-update is skipped on Windows hosts; use deploy.sh --update in Linux container",
    );
    return;
  }

  try {
    await execFileAsync(
      "sh",
      ["-c", "curl -fsSL https://gh.io/copilot-install | PREFIX=/usr/local bash"],
      { timeout: 120_000 },
    );
    logger.info("CLI updated successfully");
  } catch (err) {
    logger.error({ err }, "CLI auto-update failed");
  }
}
