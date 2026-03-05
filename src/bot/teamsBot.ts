import {
  TeamsActivityHandler,
  type TurnContext,
} from "botbuilder";
import { logger } from "../utils/logger.js";
import type { CopilotEngine } from "../engine/copilotEngine.js";

const TEAMS_MAX_MESSAGE_LENGTH = 4000;

export class AgentBot extends TeamsActivityHandler {
  private readonly engine: CopilotEngine;

  constructor(engine: CopilotEngine) {
    super();
    this.engine = engine;
  }

  protected async onMessageActivity(context: TurnContext): Promise<void> {
    const text = context.activity.text?.trim();
    if (!text) return;

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
      const response = await this.engine.chat(conversationId, text);

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

function splitMessage(text: string, maxLength: number): string[] {
  if (text.length <= maxLength) return [text];

  const chunks: string[] = [];
  let remaining = text;

  while (remaining.length > 0) {
    if (remaining.length <= maxLength) {
      chunks.push(remaining);
      break;
    }

    // Try to split at a newline or space boundary
    let splitAt = remaining.lastIndexOf("\n", maxLength);
    if (splitAt < maxLength * 0.5) {
      splitAt = remaining.lastIndexOf(" ", maxLength);
    }
    if (splitAt < maxLength * 0.3) {
      splitAt = maxLength; // Hard split
    }

    chunks.push(remaining.slice(0, splitAt));
    remaining = remaining.slice(splitAt).trimStart();
  }

  return chunks;
}
