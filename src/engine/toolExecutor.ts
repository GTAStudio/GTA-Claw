import { logger } from "../utils/logger.js";

interface RegisteredSkill {
  name: string;
  code: string;
}

/**
 * Remote skill code execution is permanently disabled.
 *
 * Product policy forbids running arbitrary JavaScript sourced from remote
 * skill payloads, and the native (Rust) phase-1 port ships with remote
 * skills disabled entirely. This class intentionally contains no script
 * engine (no node:vm, no isolated-vm, no other sandbox): it only tracks
 * skill registration metadata for diagnostics, and `execute()` always
 * rejects clearly rather than falling back to a weaker sandbox.
 */
export class ToolExecutor {
  private registeredSkills: RegisteredSkill[] = [];
  private disposed = false;

  registerSkill(name: string, code: string): void {
    // `code` is retained only as inert metadata (e.g. for future auditing);
    // it is never parsed or executed.
    this.registeredSkills.push({ name, code });
    logger.debug({ name }, "Skill registered (execution disabled)");
  }

  async execute(
    name: string,
    _params: Record<string, unknown>,
  ): Promise<unknown> {
    if (this.disposed) {
      throw new Error("ToolExecutor has been disposed");
    }

    const skill = this.registeredSkills.find((s) => s.name === name);
    if (!skill) {
      throw new Error(`Unknown skill: ${name}`);
    }

    throw new Error(
      `Remote skill execution is disabled: skill "${name}" defines executable ` +
        "code, but this deployment does not run arbitrary JavaScript from " +
        "remote skill payloads. Rewrite the skill to use a supported, " +
        "non-executable capability.",
    );
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    logger.info("ToolExecutor disposed");
  }
}
