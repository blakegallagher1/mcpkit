import { randomUUID } from 'node:crypto';

export interface SessionItem {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface Session {
  getSessionId(): string;
  getItems(limit?: number): SessionItem[];
  addItems(items: SessionItem[]): void;
  popItem(): SessionItem | undefined;
  clearSession(): void;
}

export interface SessionConfig {
  trimming?: {
    enabled: boolean;
    maxTurns?: number;
    keepLast?: number;
  };
  compaction?: {
    enabled: boolean;
    triggerTurns?: number;
    keep?: number;
    excludeTools?: string[];
    clearToolInputs?: boolean;
  };
  summarization?: {
    enabled: boolean;
    triggerTurns?: number;
    summaryPrompt?: string;
  };
}

export class InMemorySession implements Session {
  private readonly id: string;
  private items: SessionItem[] = [];
  private config: SessionConfig;

  constructor(id?: string, config?: SessionConfig) {
    this.id = id ?? randomUUID();
    this.config = config ?? {};
  }

  getSessionId(): string {
    return this.id;
  }

  getItems(limit?: number): SessionItem[] {
    if (limit !== undefined) {
      return this.items.slice(-limit);
    }
    return [...this.items];
  }

  addItems(items: SessionItem[]): void {
    this.items.push(...items);
    this.applyStrategies();
  }

  popItem(): SessionItem | undefined {
    return this.items.pop();
  }

  clearSession(): void {
    this.items = [];
  }

  private applyStrategies(): void {
    if (this.config.trimming?.enabled) {
      this.applyTrimming();
    }
    if (this.config.compaction?.enabled) {
      this.applyCompaction();
    }
    if (this.config.summarization?.enabled) {
      this.applySummarization();
    }
  }

  private applyTrimming(): void {
    const maxTurns = this.config.trimming?.maxTurns ?? 50;
    const keepLast = this.config.trimming?.keepLast ?? maxTurns;
    if (this.items.length > keepLast) {
      this.items = this.items.slice(-keepLast);
    }
  }

  private applyCompaction(): void {
    const triggerTurns = this.config.compaction?.triggerTurns ?? 20;
    const keep = this.config.compaction?.keep ?? 10;
    if (this.items.length > triggerTurns) {
      const oldItems = this.items.slice(0, this.items.length - keep);
      const summary = this.compactItems(oldItems);
      this.items = [summary, ...this.items.slice(-keep)];
    }
  }

  private compactItems(items: SessionItem[]): SessionItem {
    const contentParts = items.map(item => `[${item.role}]: ${item.content}`);
    return {
      id: randomUUID(),
      role: 'system',
      content: `[Compacted ${items.length} messages]\n${contentParts.join('\n')}`,
      timestamp: Date.now(),
      metadata: { compacted: true, originalCount: items.length }
    };
  }

  private applySummarization(): void {
    const triggerTurns = this.config.summarization?.triggerTurns ?? 30;
    if (this.items.length <= triggerTurns) return;

    const summaryPrompt = this.config.summarization?.summaryPrompt
      ?? 'Summarize the key points from the previous conversation.';

    const oldItems = this.items.slice(0, this.items.length - 5);
    const recentItems = this.items.slice(-5);

    const keyPoints = oldItems
      .filter(item => item.role !== 'system' || !item.metadata?.compacted)
      .map(item => {
        const truncated = item.content.length > 100 ? item.content.slice(0, 100) + '...' : item.content;
        return `- [${item.role}] ${truncated}`;
      });

    const summaryItem: SessionItem = {
      id: randomUUID(),
      role: 'system',
      content: `[Summary of ${oldItems.length} messages]\n${summaryPrompt}\n\nKey points:\n${keyPoints.join('\n')}`,
      timestamp: Date.now(),
      metadata: { summarized: true, originalCount: oldItems.length, strategy: 'summarization' }
    };

    this.items = [summaryItem, ...recentItems];
  }
}

export class SessionManager {
  private sessions = new Map<string, Session>();
  private defaultConfig: SessionConfig;

  constructor(defaultConfig?: SessionConfig) {
    this.defaultConfig = defaultConfig ?? {};
  }

  getOrCreate(sessionId: string): Session {
    let session = this.sessions.get(sessionId);
    if (!session) {
      session = new InMemorySession(sessionId, this.defaultConfig);
      this.sessions.set(sessionId, session);
    }
    return session;
  }

  get(sessionId: string): Session | undefined {
    return this.sessions.get(sessionId);
  }

  delete(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  listSessionIds(): string[] {
    return Array.from(this.sessions.keys());
  }

  clear(): void {
    this.sessions.clear();
  }
}

export function createSessionItem(
  role: 'user' | 'assistant' | 'system',
  content: string,
  metadata?: Record<string, unknown>
): SessionItem {
  return {
    id: randomUUID(),
    role,
    content,
    timestamp: Date.now(),
    metadata
  };
}
