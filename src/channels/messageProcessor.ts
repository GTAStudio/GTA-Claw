import { logger } from "../utils/logger.js";
import type { CopilotEngine } from "../engine/copilotEngine.js";
import type { GitHubDeviceFlow } from "../auth/deviceFlow.js";

export interface IncomingMessage {
  channel: "telegram" | "discord" | "whatsapp";
  conversationId: string;
  userName: string;
  text: string;
}

export type EngineGetter = () => CopilotEngine | null;

export async function processIncomingMessage(
  getEngine: EngineGetter,
  deviceFlow: GitHubDeviceFlow | undefined,
  input: IncomingMessage,
): Promise<string> {
  const text = input.text.trim();
  if (!text) {
    return "";
  }

  const engine = getEngine();
  if (!engine) {
    return deviceFlow
      ? deviceFlow.getAuthMessage()
      : "GTA-Claw is not configured with authentication.";
  }

  logger.info(
    {
      channel: input.channel,
      conversationId: input.conversationId,
      userName: input.userName,
      textLength: text.length,
    },
    "Incoming channel message",
  );

  try {
    return await engine.chat(input.conversationId, text);
  } catch (err) {
    logger.error(
      { err, channel: input.channel, conversationId: input.conversationId },
      "Channel message processing failed",
    );
    return "Sorry, an error occurred while processing your message. Please try again.";
  }
}
