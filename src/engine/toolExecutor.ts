import { Script, createContext } from "node:vm";
import { createRequire } from "node:module";
import { logger } from "../utils/logger.js";
import { fetch } from "../utils/proxy.js";

const ISOLATE_MEMORY_MB = 128;
const require = createRequire(import.meta.url);

/* eslint-disable @typescript-eslint/no-explicit-any */
// isolated-vm is optional — types are referenced as `any` to avoid
// compile-time dependency on the package's type declarations.
let ivm: any = null;
try {
  ivm = require("isolated-vm");
} catch {
  ivm = null;
}

interface RegisteredSkill {
  name: string;
  code: string;
}

export class ToolExecutor {
  private isolate: any = null;
  private registeredSkills: RegisteredSkill[] = [];
  private disposed = false;
  private readonly timeoutMs: number;
  private readonly allowedDomains: string[];
  private readonly mode: "isolated-vm" | "node-vm";

  constructor(timeoutMs: number, allowedDomains: string[]) {
    this.timeoutMs = timeoutMs;
    this.allowedDomains = allowedDomains;

    if (ivm) {
      this.mode = "isolated-vm";
      this.isolate = this.createIsolate();
      logger.info("ToolExecutor using isolated-vm backend");
    } else {
      this.mode = "node-vm";
      logger.warn(
        "isolated-vm not available; falling back to node:vm sandbox (reduced isolation)",
      );
    }
  }

  private createIsolate(): any {
    if (!ivm) {
      throw new Error("isolated-vm backend is not available");
    }

    return new ivm.Isolate({
      memoryLimit: ISOLATE_MEMORY_MB,
      onCatastrophicError: (err: Error) => {
        logger.fatal({ err }, "Isolate catastrophic error — recreating");
        this.recoverIsolate();
      },
    });
  }

  private recoverIsolate(): void {
    if (!this.isolate) return;

    try {
      this.isolate.dispose();
    } catch {
      // Already dead
    }
    this.isolate = this.createIsolate();
    logger.info("Isolate recreated after catastrophic error");
  }

  registerSkill(name: string, code: string): void {
    this.registeredSkills.push({ name, code });
    logger.debug({ name }, "Skill registered in executor");
  }

  private isDomainAllowed(url: string): boolean {
    if (this.allowedDomains.length === 0) return true; // No whitelist = allow all
    try {
      const hostname = new URL(url).hostname;
      return this.allowedDomains.some(
        (d) => hostname === d || hostname.endsWith(`.${d}`),
      );
    } catch {
      return false;
    }
  }

  async execute(
    name: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    if (this.disposed) {
      throw new Error("ToolExecutor has been disposed");
    }

    const skill = this.registeredSkills.find((s) => s.name === name);
    if (!skill) {
      throw new Error(`Unknown skill: ${name}`);
    }

    if (this.mode === "node-vm") {
      return this.executeWithNodeVm(skill.code, name, params);
    }

    return this.executeWithIsolate(skill.code, name, params);
  }

  private async executeWithNodeVm(
    skillCode: string,
    skillName: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    const api = {
      httpGet: async (url: string): Promise<string> => {
        if (typeof url !== "string") throw new Error("url must be a string");
        if (!this.isDomainAllowed(url)) {
          throw new Error(`Domain not allowed: ${url}`);
        }
        const resp = await fetch(url, {
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        return resp.text();
      },
      httpPost: async (
        url: string,
        body: string,
        headers: Record<string, string> = {},
      ): Promise<string> => {
        if (typeof url !== "string") throw new Error("url must be a string");
        if (!this.isDomainAllowed(url)) {
          throw new Error(`Domain not allowed: ${url}`);
        }
        const resp = await fetch(url, {
          method: "POST",
          body,
          headers,
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        return resp.text();
      },
      log: (msg: unknown): void => {
        const sanitized = String(msg).slice(0, 2000);
        logger.info({ skill: skillName }, `[skill] ${sanitized}`);
      },
    };

    const sandbox: {
      params: Record<string, unknown>;
      api: typeof api;
      result?: unknown;
    } = { params, api, result: undefined };

    const context = createContext(sandbox);
    const script = new Script(
      `
      const fn = ${skillCode};
      result = fn(params, api);
      `,
    );

    script.runInContext(context, { timeout: this.timeoutMs });
    return Promise.resolve(sandbox.result);
  }

  private async executeWithIsolate(
    skillCode: string,
    skillName: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    if (!ivm || !this.isolate) {
      throw new Error("isolated-vm backend is not available");
    }

    const context = await this.isolate.createContext();

    try {
      const jail = context.global;
      await jail.set("global", jail.derefInto);

      // Inject API bridges as callbacks
      await jail.set(
        "$httpGet",
        new ivm.Callback(async (url: string) => {
          if (typeof url !== "string") throw new Error("url must be a string");
          if (!this.isDomainAllowed(url)) {
            throw new Error(`Domain not allowed: ${url}`);
          }
          const resp = await fetch(url, {
            signal: AbortSignal.timeout(this.timeoutMs),
          });
          return resp.text();
        }),
      );

      await jail.set(
        "$httpPost",
        new ivm.Callback(
          async (url: string, body: string, headersJson: string) => {
            if (typeof url !== "string")
              throw new Error("url must be a string");
            if (!this.isDomainAllowed(url)) {
              throw new Error(`Domain not allowed: ${url}`);
            }
            const headers: Record<string, string> = headersJson
              ? (JSON.parse(headersJson) as Record<string, string>)
              : {};
            const resp = await fetch(url, {
              method: "POST",
              body,
              headers,
              signal: AbortSignal.timeout(this.timeoutMs),
            });
            return resp.text();
          },
        ),
      );

      await jail.set(
        "$log",
        new ivm.Callback((msg: string) => {
          const sanitized = String(msg).slice(0, 2000);
          logger.info({ skill: skillName }, `[skill] ${sanitized}`);
        }),
      );

      // Execute the skill code with params and API bridges
      const result = await context.evalClosure(
        `
        const api = {
          httpGet: async (url) => $httpGet.apply(undefined, [url], { result: { promise: true } }),
          httpPost: async (url, body, headers) => $httpPost.apply(undefined, [url, body, JSON.stringify(headers || {})], { result: { promise: true } }),
          log: (msg) => $log.apply(undefined, [String(msg)])
        };
        const fn = ${skillCode};
        return fn($0, api);
        `,
        [new ivm.ExternalCopy(params).copyInto()],
        { timeout: this.timeoutMs, result: { promise: true } },
      );

      return result;
    } finally {
      context.release();
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (!this.isolate) {
      logger.info("ToolExecutor disposed");
      return;
    }

    try {
      this.isolate.dispose();
    } catch {
      // Already disposed
    }
    logger.info("ToolExecutor disposed");
  }
}
