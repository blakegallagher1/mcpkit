export interface ToolFilterStatic {
  allowedToolNames?: string[];
  blockedToolNames?: string[];
}

export interface ToolFilterContext {
  toolName: string;
  serverName: string;
  clientId?: string;
  scopes?: string[];
}

export type ToolFilterCallable = (context: ToolFilterContext) => boolean | Promise<boolean>;

export type ToolFilter = ToolFilterCallable | ToolFilterStatic | null;

export function createStaticToolFilter(
  allowedToolNames?: string[],
  blockedToolNames?: string[]
): ToolFilterStatic | null {
  if (!allowedToolNames && !blockedToolNames) return null;
  const filter: ToolFilterStatic = {};
  if (allowedToolNames) filter.allowedToolNames = allowedToolNames;
  if (blockedToolNames) filter.blockedToolNames = blockedToolNames;
  return filter;
}

export function applyStaticFilter(filter: ToolFilterStatic, toolName: string): boolean {
  if (filter.allowedToolNames && !filter.allowedToolNames.includes(toolName)) {
    return false;
  }
  if (filter.blockedToolNames && filter.blockedToolNames.includes(toolName)) {
    return false;
  }
  return true;
}

export async function applyToolFilter(
  filter: ToolFilter,
  context: ToolFilterContext
): Promise<boolean> {
  if (filter === null || filter === undefined) return true;

  if (typeof filter === 'function') {
    const result = filter(context);
    return result instanceof Promise ? await result : result;
  }

  return applyStaticFilter(filter, context.toolName);
}

export function detectDuplicateToolNames(toolNames: string[]): string[] {
  const seen = new Set<string>();
  const duplicates: string[] = [];
  for (const name of toolNames) {
    if (seen.has(name)) {
      duplicates.push(name);
    }
    seen.add(name);
  }
  return duplicates;
}
