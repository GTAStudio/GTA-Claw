import { loadConfig } from "./config.js";
import { logger } from "./utils/logger.js";
import { setupProxy } from "./utils/proxy.js";
import { loadRole } from "./loader/roleLoader.js";
import { loadSkills } from "./loader/skillLoader.js";
import { ToolExecutor } from "./engine/toolExecutor.js";
import { CopilotEngine } from "./engine/copilotEngine.js";
import { AgentBot } from "./bot/teamsBot.js";
import { createServer } from "./server.js";
import { checkForUpdates } from "./updater/sdkUpdater.js";
import { GitHubDeviceFlow } from "./auth/deviceFlow.js";
import { processIncomingMessage } from "./channels/messageProcessor.js";
import { TelegramPollingClient } from "./channels/telegramPolling.js";
import { DiscordGatewayClient } from "./channels/discordGateway.js";
import { WhatsAppWebhookHandler } from "./channels/whatsappWebhook.js";

async function main(): Promise<void> {
  logger.info("=== GTA-Claw Engine Starting ===");

  // 0. Configure HTTP proxy (if HTTPS_PROXY / HTTP_PROXY is set)
  setupProxy();

  // 1. Load and validate configuration
  const config = loadConfig();

  // 2. Load role + skills in parallel
  const [roleResult, skillsResult] = await Promise.allSettled([
    loadRole(config.AGENT_ROLE_URL),
    loadSkills(config.ENABLED_SKILLS),
  ]);

  // Role is critical — fail if it cannot be loaded
  if (roleResult.status === "rejected") {
    logger.fatal({ error: roleResult.reason }, "Failed to load role — cannot start");
    process.exit(1);
  }
  let roleConfig = roleResult.value;

  // Skills are non-critical — warn and continue with whatever loaded
  let skills =
    skillsResult.status === "fulfilled" ? skillsResult.value : [];
  if (skillsResult.status === "rejected") {
    logger.error(
      { error: skillsResult.reason },
      "Failed to load skills — starting with zero skills",
    );
  }

  // 3. Set up isolated-vm sandbox and register skills
  let toolExecutor = new ToolExecutor(
    config.SKILL_EXEC_TIMEOUT_MS,
    config.ALLOWED_SKILL_DOMAINS,
  );
  let reloadInProgress = false;
  for (const skill of skills) {
    toolExecutor.registerSkill(skill.name, skill.executeCode);
  }

  // 4. Initialize active engine if token exists (OAuth mode can bootstrap later)
  let engine: CopilotEngine | null = null;
  let engineSwitchPromise: Promise<void> | null = null;

  const activateEngineWithToken = async (
    githubToken: string,
    source: string,
  ): Promise<void> => {
    if (engineSwitchPromise) {
      await engineSwitchPromise;
    }

    engineSwitchPromise = (async () => {
      logger.info({ source }, "Activating Copilot engine with token");
      const nextEngine = new CopilotEngine(
        config,
        roleConfig,
        skills,
        toolExecutor,
        githubToken,
      );
      await nextEngine.start();

      const prevEngine = engine;
      engine = nextEngine;

      if (prevEngine) {
        await prevEngine.stop();
      }
    })();

    try {
      await engineSwitchPromise;
    } finally {
      engineSwitchPromise = null;
    }
  };

  if (config.GITHUB_TOKEN) {
    await activateEngineWithToken(config.GITHUB_TOKEN, "startup:GITHUB_TOKEN");
  } else {
    logger.warn(
      "No GITHUB_TOKEN configured at startup; waiting for OAuth authorization",
    );
  }

  const deviceFlow = config.DEVICE_FLOW_ENABLED
    ? new GitHubDeviceFlow({
        clientId: config.GITHUB_CLIENT_ID!,
        onTokenAcquired: async (token, login) => {
          await activateEngineWithToken(token, `device-flow:${login}`);
        },
      })
    : undefined;

  const processChannelMessage = async (input: {
    channel: "telegram" | "discord" | "whatsapp";
    conversationId: string;
    userName: string;
    text: string;
  }): Promise<string> =>
    processIncomingMessage(() => engine, deviceFlow, input);

  const telegramClient = config.ENABLE_TELEGRAM
    ? new TelegramPollingClient({
        botToken: config.TELEGRAM_BOT_TOKEN!,
        pollIntervalMs: config.TELEGRAM_POLL_INTERVAL_MS,
        onMessage: async (msg) =>
          processChannelMessage({ channel: "telegram", ...msg }),
      })
    : null;

  const discordClient = config.ENABLE_DISCORD
    ? new DiscordGatewayClient({
        botToken: config.DISCORD_BOT_TOKEN!,
        gatewayUrl: config.DISCORD_GATEWAY_URL,
        intents: config.DISCORD_GATEWAY_INTENTS,
        onMessage: async (msg) =>
          processChannelMessage({ channel: "discord", ...msg }),
      })
    : null;

  const whatsappHandler = config.ENABLE_WHATSAPP
    ? new WhatsAppWebhookHandler({
        verifyToken: config.WHATSAPP_VERIFY_TOKEN!,
        accessToken: config.WHATSAPP_ACCESS_TOKEN!,
        phoneNumberId: config.WHATSAPP_PHONE_NUMBER_ID!,
        onMessage: async (msg) =>
          processChannelMessage({ channel: "whatsapp", ...msg }),
      })
    : undefined;

  // 5. Create Teams bot
  const bot = new AgentBot(() => engine, deviceFlow);

  // 6. Create and start HTTP server
  const server = createServer({
    bot,
    config,
    getEngine: () => engine,
    whatsappHandler,
    getRuntimeStatus: () => ({
      skillCount: skills.length,
      activeModel: roleConfig.model ?? config.COPILOT_MODEL,
    }),
    reloadFn: async () => {
      if (reloadInProgress) {
        throw new Error("Reload already in progress");
      }
      reloadInProgress = true;

      logger.info("Admin reload requested");
      try {
        const [newRoleResult, newSkillsResult] = await Promise.allSettled([
          loadRole(config.AGENT_ROLE_URL),
          loadSkills(config.ENABLED_SKILLS),
        ]);

        if (newRoleResult.status === "rejected") {
          throw new Error(`Role reload failed: ${String(newRoleResult.reason)}`);
        }

        const nextRole = newRoleResult.value;
        const nextSkills =
          newSkillsResult.status === "fulfilled" ? newSkillsResult.value : skills;

        if (newSkillsResult.status === "rejected") {
          logger.warn(
            { error: newSkillsResult.reason },
            "Skill reload failed; keeping previous skills",
          );
        }

        const nextExecutor = new ToolExecutor(
          config.SKILL_EXEC_TIMEOUT_MS,
          config.ALLOWED_SKILL_DOMAINS,
        );
        try {
          for (const skill of nextSkills) {
            nextExecutor.registerSkill(skill.name, skill.executeCode);
          }

          if (engine) {
            engine.reload(nextRole, nextSkills, nextExecutor);
          }
          toolExecutor.dispose();

          roleConfig = nextRole;
          skills = nextSkills;
          toolExecutor = nextExecutor;
        } catch (err) {
          nextExecutor.dispose();
          throw err;
        }

        logger.info(
          {
            model: roleConfig.model ?? config.COPILOT_MODEL,
            skills: skills.length,
          },
          "Admin reload completed",
        );

        return { roleModel: roleConfig.model, skillCount: skills.length };
      } finally {
        reloadInProgress = false;
      }
    },
  });

  server.listen(config.PORT, () => {
    logger.info(
      {
        port: config.PORT,
        model: roleConfig.model ?? config.COPILOT_MODEL,
        skills: skills.length,
        domain: config.DOMAIN,
      },
      `GTA-Claw engine ready. Skills: ${skills.length} loaded.`,
    );
  });

  if (telegramClient) {
    await telegramClient.start();
  }
  if (discordClient) {
    discordClient.start();
  }

  // 7. Non-blocking SDK/CLI update check
  checkForUpdates(config.AUTO_UPDATE).catch((err) => {
    logger.warn({ err }, "SDK/CLI update check failed (non-blocking)");
  });

  // 8. Graceful shutdown handlers
  let shutdownPromise: Promise<void> | null = null;
  const gracefulShutdown = async (signal: string): Promise<void> => {
    if (shutdownPromise) {
      logger.warn({ signal }, "Shutdown already in progress");
      return shutdownPromise;
    }

    shutdownPromise = (async () => {
    logger.info({ signal }, "Shutdown signal received");

    server.close();
    if (deviceFlow) {
      deviceFlow.stop();
    }
    if (telegramClient) {
      await telegramClient.stop();
    }
    if (discordClient) {
      await discordClient.stop();
    }
    if (engine) {
      await engine.stop();
    }
    toolExecutor.dispose();

    logger.info("GTA-Claw engine shut down cleanly");
    process.exit(0);
    })();

    return shutdownPromise;
  };

  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdown("SIGINT"));
}

main().catch((err) => {
  logger.fatal({ err }, "Fatal startup error");
  process.exit(1);
});
