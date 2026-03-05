import { loadConfig } from "./config.js";
import { logger } from "./utils/logger.js";
import { loadRole } from "./loader/roleLoader.js";
import { loadSkills } from "./loader/skillLoader.js";
import { ToolExecutor } from "./engine/toolExecutor.js";
import { CopilotEngine } from "./engine/copilotEngine.js";
import { AgentBot } from "./bot/teamsBot.js";
import { createServer } from "./server.js";
import { checkForUpdates } from "./updater/sdkUpdater.js";

async function main(): Promise<void> {
  logger.info("=== GTA-Claw Engine Starting ===");

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

  // 4. Initialize AI engine
  const engine = new CopilotEngine(config, roleConfig, skills, toolExecutor);
  await engine.start();

  // 5. Create Teams bot
  const bot = new AgentBot(engine);

  // 6. Create and start HTTP server
  const server = createServer({
    bot,
    config,
    engine,
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

          engine.reload(nextRole, nextSkills, nextExecutor);
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
    await engine.stop();
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
