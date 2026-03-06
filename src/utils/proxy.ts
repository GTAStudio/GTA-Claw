import { ProxyAgent, setGlobalDispatcher } from "undici";
import { logger } from "./logger.js";

/**
 * If HTTP_PROXY / HTTPS_PROXY / ALL_PROXY is set, configure undici's global
 * dispatcher so that every `fetch()` call (including inside the skill sandbox)
 * goes through the proxy automatically.
 *
 * Call this once at startup, before any HTTP requests are made.
 */
export function setupProxy(): void {
  const proxyUrl =
    process.env["HTTPS_PROXY"] ||
    process.env["https_proxy"] ||
    process.env["HTTP_PROXY"] ||
    process.env["http_proxy"] ||
    process.env["ALL_PROXY"] ||
    process.env["all_proxy"];

  if (!proxyUrl) {
    logger.debug("No HTTP proxy configured");
    return;
  }

  try {
    const agent = new ProxyAgent(proxyUrl);
    setGlobalDispatcher(agent);
    logger.info({ proxy: proxyUrl.replace(/\/\/.*@/, "//<redacted>@") }, "Global HTTP proxy configured");
  } catch (err) {
    logger.error({ err, proxy: proxyUrl }, "Failed to configure HTTP proxy — continuing without proxy");
  }
}
