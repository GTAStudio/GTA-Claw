import { logger } from "../utils/logger.js";
import type { CopilotEngine } from "../engine/copilotEngine.js";

export interface IncomingMessage {
  channel: "telegram" | "discord" | "whatsapp";
  conversationId: string;
  userName: string;
  text: string;
}

export type EngineGetter = () => CopilotEngine | null;

export async function processIncomingMessage(
  getEngine: EngineGetter,
  oauthLoginPath: string | undefined,
  input: IncomingMessage,
): Promise<string> {
  const text = input.text.trim();
  if (!text) {
    return "";
  }

  const engine = getEngine();
  if (!engine) {
    return oauthLoginPath
      ? `GTA-Claw 尚未完成授权，请先访问: ${oauthLoginPath}`
      : "GTA-Claw 尚未配置有效鉴权。";
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
    return "抱歉，处理消息时发生错误，请稍后再试。";
  }
}
