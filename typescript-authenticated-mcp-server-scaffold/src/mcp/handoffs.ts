export interface HandoffAgent {
  name: string;
  description?: string;
  handoffDescription?: string;
  tools?: string[];
  instructions?: string;
}

export interface HandoffInputData {
  inputHistory: unknown[];
  preHandoffItems: unknown[];
  newItems: unknown[];
  context?: Record<string, unknown>;
}

export type HandoffInputFilter = (input: HandoffInputData) => HandoffInputData;

export interface HandoffConfig {
  toolNameOverride?: string;
  toolDescriptionOverride?: string;
  onHandoff?: (input: unknown) => Promise<void> | void;
  inputFilter?: HandoffInputFilter;
  isEnabled?: boolean | ((context: Record<string, unknown>) => boolean | Promise<boolean>);
}

export class Handoff {
  readonly toolName: string;
  readonly toolDescription: string;
  readonly agentName: string;
  readonly agent: HandoffAgent;
  readonly inputFilter?: HandoffInputFilter;
  private readonly isEnabled: boolean | ((context: Record<string, unknown>) => boolean | Promise<boolean>);
  private readonly onHandoff?: (input: unknown) => Promise<void> | void;

  constructor(agent: HandoffAgent, config?: HandoffConfig) {
    this.agent = agent;
    this.agentName = agent.name;
    this.toolName = config?.toolNameOverride ?? defaultHandoffToolName(agent.name);
    this.toolDescription = config?.toolDescriptionOverride ?? defaultHandoffToolDescription(agent);
    this.inputFilter = config?.inputFilter;
    this.isEnabled = config?.isEnabled ?? true;
    this.onHandoff = config?.onHandoff;
  }

  async checkEnabled(context: Record<string, unknown> = {}): Promise<boolean> {
    if (typeof this.isEnabled === 'boolean') return this.isEnabled;
    return Promise.resolve(this.isEnabled(context));
  }

  async invoke(input: unknown): Promise<{ agent: HandoffAgent; transferMessage: string }> {
    if (this.onHandoff) {
      await Promise.resolve(this.onHandoff(input));
    }
    return {
      agent: this.agent,
      transferMessage: getTransferMessage(this.agent)
    };
  }

  getAsFunctionTool() {
    return {
      type: 'function' as const,
      name: this.toolName,
      description: this.toolDescription,
      parameters: {
        type: 'object' as const,
        properties: {
          reason: {
            type: 'string' as const,
            description: 'Reason for the handoff'
          }
        },
        required: ['reason'] as const
      },
      strict: true
    };
  }
}

function toFunctionToolName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_|_$/g, '');
}

function defaultHandoffToolName(agentName: string): string {
  return `transfer_to_${toFunctionToolName(agentName)}`;
}

function defaultHandoffToolDescription(agent: HandoffAgent): string {
  const base = `Handoff to the ${agent.name} agent to handle the request.`;
  return agent.handoffDescription ? `${base} ${agent.handoffDescription}` : base;
}

function getTransferMessage(agent: HandoffAgent): string {
  return JSON.stringify({ assistant: agent.name });
}

export class HandoffRegistry {
  private handoffs = new Map<string, Handoff>();

  register(handoff: Handoff): void {
    this.handoffs.set(handoff.toolName, handoff);
  }

  get(toolName: string): Handoff | undefined {
    return this.handoffs.get(toolName);
  }

  async getEnabledHandoffs(context: Record<string, unknown> = {}): Promise<Handoff[]> {
    const results: Handoff[] = [];
    for (const handoff of this.handoffs.values()) {
      if (await handoff.checkEnabled(context)) {
        results.push(handoff);
      }
    }
    return results;
  }

  getAllFunctionTools(): ReturnType<Handoff['getAsFunctionTool']>[] {
    return Array.from(this.handoffs.values()).map(h => h.getAsFunctionTool());
  }

  list(): Handoff[] {
    return Array.from(this.handoffs.values());
  }
}
