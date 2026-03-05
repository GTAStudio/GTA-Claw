import { logger } from "../utils/logger.js";

interface SessionEntry {
  session: unknown; // CopilotSession — typed as unknown since SDK types may vary
  lastAccess: number;
}

export class SessionManager {
  private readonly sessions = new Map<string, SessionEntry>();
  private readonly ttlMs: number;
  private readonly maxSessions: number;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(ttlMs: number, maxSessions: number) {
    this.ttlMs = ttlMs;
    this.maxSessions = maxSessions;

    // Run cleanup every 60 seconds
    this.cleanupTimer = setInterval(() => this.cleanup(), 60_000);
    this.cleanupTimer.unref(); // Don't prevent process exit
  }

  get(conversationId: string): unknown | undefined {
    const entry = this.sessions.get(conversationId);
    if (entry) {
      entry.lastAccess = Date.now();
      return entry.session;
    }
    return undefined;
  }

  set(conversationId: string, session: unknown): void {
    // Enforce MAX_SESSIONS — evict LRU if at capacity
    if (
      this.sessions.size >= this.maxSessions &&
      !this.sessions.has(conversationId)
    ) {
      this.evictLRU();
    }

    this.sessions.set(conversationId, {
      session,
      lastAccess: Date.now(),
    });

    logger.debug(
      { conversationId, totalSessions: this.sessions.size },
      "Session stored",
    );
  }

  has(conversationId: string): boolean {
    return this.sessions.has(conversationId);
  }

  get size(): number {
    return this.sessions.size;
  }

  private cleanup(): void {
    const now = Date.now();
    let expired = 0;

    for (const [id, entry] of this.sessions) {
      if (now - entry.lastAccess > this.ttlMs) {
        this.sessions.delete(id);
        expired++;
      }
    }

    if (expired > 0) {
      logger.info(
        { expired, remaining: this.sessions.size },
        "Session cleanup complete",
      );
    }
  }

  private evictLRU(): void {
    let oldestId: string | null = null;
    let oldestTime = Infinity;

    for (const [id, entry] of this.sessions) {
      if (entry.lastAccess < oldestTime) {
        oldestTime = entry.lastAccess;
        oldestId = id;
      }
    }

    if (oldestId) {
      this.sessions.delete(oldestId);
      logger.warn(
        { evictedId: oldestId, maxSessions: this.maxSessions },
        "Session evicted (LRU) — max capacity reached",
      );
    }
  }

  clear(): void {
    const count = this.sessions.size;
    this.sessions.clear();
    logger.info({ cleared: count }, "All active sessions cleared");
  }

  destroyAll(): void {
    const count = this.sessions.size;
    this.sessions.clear();

    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    logger.info({ destroyed: count }, "All sessions destroyed");
  }
}
