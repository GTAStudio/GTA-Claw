import {
  TeamsActivityHandler,
  type TurnContext,
} from "botbuilder";
import { logger } from "../utils/logger.js";
import { splitMessage } from "../utils/splitMessage.js";
import type { CopilotEngine } from "../engine/copilotEngine.js";
import type { GitHubDeviceFlow } from "../auth/deviceFlow.js";

const TEAMS_MAX_MESSAGE_LENGTH = 4000;

export class AgentBot extends TeamsActivityHandler {
  private readonly getEngine: () => CopilotEngine | null;
  private readonly deviceFlow: GitHubDeviceFlow | undefined;

  constructor(
    getEngine: () => CopilotEngine | null,
    deviceFlow?: GitHubDeviceFlow,
  ) {
    super();
    this.getEngine = getEngine;
    this.deviceFlow = deviceFlow;
  }

  protected async onMessageActivity(context: TurnContext): Promise<void> {
    const text = context.activity.text?.trim();
    if (!text) return;

    const engine = this.getEngine();
    if (!engine) {
      const authHint = this.deviceFlow
        ? await this.deviceFlow.getAuthMessage()
        : "No active GitHub token is configured.";
      await context.sendActivity(
        `GTA-Claw is not authenticated yet. ${authHint}`,
      );
      return;
    }

    const conversationId = context.activity.conversation?.id;
    if (!conversationId) {
      logger.warn("Message received without conversation ID");
      return;
    }

    const userName = context.activity.from?.name ?? "Unknown";
    logger.info({ conversationId, userName, textLength: text.length }, "Message received");

    // Send typing indicator
    await context.sendActivities([{ type: "typing" }]);

    try {
      const response = await engine.chat(conversationId, text);

      // Split long messages for Teams 4000-char limit
      const chunks = splitMessage(response, TEAMS_MAX_MESSAGE_LENGTH);
      for (const chunk of chunks) {
        await context.sendActivity(chunk);
      }
    } catch (err) {
      logger.error({ err, conversationId }, "Error processing message");
      await context.sendActivity(
        "I'm sorry, an error occurred while processing your message. Please try again.",
      );
    }
  }

  protected async onTeamsMembersAdded(context: TurnContext): Promise<void> {
    const membersAdded = context.activity.membersAdded ?? [];
    for (const member of membersAdded) {
      if (member.id !== context.activity.recipient?.id) {
        await context.sendActivity(
          "Hello! I'm GTA-Claw, your AI assistant. How can I help you today?",
        );
      }
    }
  }

  protected async onTeamsMessageEdit(context: TurnContext): Promise<void> {
    // Treat edited messages as new messages
    await this.onMessageActivity(context);
  }
}
