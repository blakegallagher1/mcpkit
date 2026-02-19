export class MCPError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(message: string, status: number = 500, code: string = 'server_error') {
    super(message);
    this.name = 'MCPError';
    this.status = status;
    this.code = code;
  }

  static generate(status: number, message: string): MCPError {
    if (status === 400) return new BadRequestError(message);
    if (status === 401) return new AuthenticationError(message);
    if (status === 403) return new PermissionDeniedError(message);
    if (status === 404) return new NotFoundError(message);
    if (status === 409) return new ConflictError(message);
    if (status === 422) return new ValidationError(message);
    if (status === 429) return new RateLimitError(message);
    if (status >= 500) return new InternalServerError(message);
    return new MCPError(message, status);
  }

  toToolResult() {
    return {
      isError: true as const,
      content: [{ type: 'text' as const, text: JSON.stringify({ error: this.code, detail: this.message }) }]
    };
  }
}

export class BadRequestError extends MCPError {
  constructor(message: string = 'Bad request') {
    super(message, 400, 'bad_request');
    this.name = 'BadRequestError';
  }
}

export class AuthenticationError extends MCPError {
  constructor(message: string = 'Authentication required') {
    super(message, 401, 'authentication_error');
    this.name = 'AuthenticationError';
  }
}

export class PermissionDeniedError extends MCPError {
  constructor(message: string = 'Permission denied') {
    super(message, 403, 'permission_denied');
    this.name = 'PermissionDeniedError';
  }
}

export class NotFoundError extends MCPError {
  constructor(message: string = 'Not found') {
    super(message, 404, 'not_found');
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends MCPError {
  constructor(message: string = 'Conflict') {
    super(message, 409, 'conflict');
    this.name = 'ConflictError';
  }
}

export class ValidationError extends MCPError {
  constructor(message: string = 'Validation error') {
    super(message, 422, 'validation_error');
    this.name = 'ValidationError';
  }
}

export class RateLimitError extends MCPError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 429, 'rate_limit_exceeded');
    this.name = 'RateLimitError';
  }
}

export class InternalServerError extends MCPError {
  constructor(message: string = 'Internal server error') {
    super(message, 500, 'internal_server_error');
    this.name = 'InternalServerError';
  }
}

export class ConnectionError extends MCPError {
  readonly cause?: Error;
  constructor(message: string = 'Connection error', cause?: Error) {
    super(message, 0, 'connection_error');
    this.name = 'ConnectionError';
    this.cause = cause;
  }
}

export class ConnectionTimeoutError extends ConnectionError {
  constructor(message: string = 'Request timed out') {
    super(message);
    this.name = 'ConnectionTimeoutError';
  }
}

export class MaxTurnsExceededError extends MCPError {
  constructor(maxTurns: number) {
    super(`Maximum turns exceeded: ${maxTurns}`, 400, 'max_turns_exceeded');
    this.name = 'MaxTurnsExceededError';
  }
}

export class GuardrailTripwireError extends MCPError {
  readonly guardrailName: string;
  readonly output: unknown;
  constructor(guardrailName: string, output?: unknown) {
    super(`Guardrail tripwire triggered: ${guardrailName}`, 400, 'guardrail_tripwire');
    this.name = 'GuardrailTripwireError';
    this.guardrailName = guardrailName;
    this.output = output;
  }
}

export function nonFatalToolError(error: unknown, toolName: string) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[tool-error] Non-fatal error in tool "${toolName}":`, message);
  return {
    isError: true as const,
    content: [{ type: 'text' as const, text: JSON.stringify({ error: 'Tool execution failed', tool: toolName, detail: message }) }]
  };
}

export function wrapToolHandler<TInput, TResult>(
  toolName: string,
  handler: (input: TInput) => Promise<TResult>
): (input: TInput) => Promise<TResult | ReturnType<typeof nonFatalToolError>> {
  return async (input: TInput) => {
    try {
      return await handler(input);
    } catch (error) {
      return nonFatalToolError(error, toolName);
    }
  };
}
