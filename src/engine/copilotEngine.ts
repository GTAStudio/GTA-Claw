import { CopilotClient, CopilotSession, defineTool, approveAll } from "@github/copilot-sdk";
import type { Tool } from "@github/copilot-sdk";
import { logger } from "../utils/logger.js";
import { SessionManager } from "./sessionManager.js";
import type { ToolExecutor } from "./toolExecutor.js";
import type { Skill } from "../loader/skillLoader.js";
import type { RoleConfig } from "../loader/roleLoader.js";
import type { AppConfig } from "../config.js";

export class CopilotEngine {
  private readonly client: CopilotClient;
  private readonly sessionManager: SessionManager;
  private readonly config: AppConfig;
  private roleConfig: RoleConfig;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private tools: Tool<any>[] = [];

  constructor(
    config: AppConfig,
    roleConfig: RoleConfig,
    skills: Skill[],
    toolExecutor: ToolExecutor,
  ) {
    this.config = config;
    this.roleConfig = roleConfig;

    this.client = new CopilotClient({
      githubToken: config.GITHUB_TOKEN,
      autoRestart: true,
    });

    this.sessionManager = new SessionManager(
      config.SESSION_TTL_MS,
      config.MAX_SESSIONS,
    );

    this.buildTools(skills, toolExecutor);
  }

  private buildTools(skills: Skill[], toolExecutor: ToolExecutor): void {
    this.tools = skills.map((skill) =>
      defineTool(skill.name, {
        description: skill.description,
        parameters: skill.parameters,
        handler: async (args: Record<string, unknown>) => {
          logger.info({ tool: skill.name, args }, "Tool invoked");
          try {
            const result = await toolExecutor.execute(skill.name, args);
            logger.info(
              { tool: skill.name, success: true },
              "Tool execution complete",
            );
            return result;
          } catch (err) {
            logger.error(
              { tool: skill.name, err },
              "Tool execution failed",
            );
            throw err;
          }
        },
      }),
    );

    logger.info({ toolCount: this.tools.length }, "Tools built from skills");
  }

  async start(): Promise<void> {
    logger.info("Starting CopilotClient...");
    await this.client.start();

    try {
      await this.client.ping();
      logger.info("CopilotClient started — ping successful");
    } catch (err) {
      logger.error({ err }, "CopilotClient ping failed after start");
      throw err;
    }
  }

  async chat(conversationId: string, message: string): Promise<string> {
    let session = this.sessionManager.get(conversationId) as CopilotSession | undefined;

    if (!session) {
      const model = this.roleConfig.model ?? this.config.COPILOT_MODEL;
      logger.info(
        { conversationId, model },
        "Creating new session for conversation",
      );

      session = await this.client.createSession({
        sessionId: conversationId,
        model,
        tools: this.tools,
        systemMessage: {
          mode: "replace",
          content: this.roleConfig.content,
        },
        infiniteSessions: { enabled: true },
        onPermissionRequest: approveAll,
        hooks: {
          onPreToolUse: (input: { toolName: string }) => {
            const toolExists = this.tools.some(
              (t) => t.name === input.toolName,
            );
            if (!toolExists) {
              logger.warn(
                { toolName: input.toolName },
                "Unknown tool invocation blocked",
              );
              return { permissionDecision: "deny" as const };
            }
            logger.debug(
              { toolName: input.toolName, conversationId },
              "Tool use approved",
            );
            return { permissionDecision: "allow" as const };
          },
          onPostToolUse: (input: { toolName: string }) => {
            logger.debug(
              { toolName: input.toolName, conversationId },
              "Tool use completed",
            );
          },
          onErrorOccurred: (input: { error: unknown }) => {
            logger.error(
              { error: input.error, conversationId },
              "Session error occurred",
            );
            return { errorHandling: "skip" as const };
          },
        },
      });

      this.sessionManager.set(conversationId, session);
    }

    try {
      const event = await session.sendAndWait(
        { prompt: message },
        this.config.SDK_REQUEST_TIMEOUT_MS,
      );
      return event?.data?.content ?? "(No response from AI)";
    } catch (err) {
      logger.error({ err, conversationId }, "chat() failed");
      return "Sorry, I encountered an error processing your request. Please try again.";
    }
  }

  get sessionCount(): number {
    return this.sessionManager.size;
  }

  reload(roleConfig: RoleConfig, skills: Skill[], toolExecutor: ToolExecutor): void {
    this.roleConfig = roleConfig;
    this.buildTools(skills, toolExecutor);
    // Force new sessions so updated role/tools are applied consistently.
    this.sessionManager.clear();
    logger.info(
      { model: roleConfig.model ?? this.config.COPILOT_MODEL, skills: skills.length },
      "CopilotEngine reloaded",
    );
  }

  async stop(): Promise<void> {
    logger.info("Stopping CopilotEngine...");
    this.sessionManager.destroyAll();
    try {
      await this.client.stop();
    } catch {
      logger.warn("Graceful stop failed, forcing...");
      await this.client.forceStop();
    }
    logger.info("CopilotEngine stopped");
  }
}
