import { GuardrailTripwireError } from './errors.js';

export interface GuardrailOutput {
  tripwireTriggered: boolean;
  outputInfo?: unknown;
}

export interface InputGuardrail {
  name: string;
  execute: (input: unknown, context?: Record<string, unknown>) => Promise<GuardrailOutput> | GuardrailOutput;
  runInParallel?: boolean;
}

export interface OutputGuardrail {
  name: string;
  execute: (output: unknown, context?: Record<string, unknown>) => Promise<GuardrailOutput> | GuardrailOutput;
  runInParallel?: boolean;
}

export interface GuardrailResult {
  guardrailName: string;
  output: GuardrailOutput;
  passed: boolean;
}

export async function runInputGuardrails(
  guardrails: InputGuardrail[],
  input: unknown,
  context?: Record<string, unknown>
): Promise<GuardrailResult[]> {
  const parallelGuardrails = guardrails.filter(g => g.runInParallel !== false);
  const blockingGuardrails = guardrails.filter(g => g.runInParallel === false);

  const results: GuardrailResult[] = [];

  for (const guardrail of blockingGuardrails) {
    const output = await Promise.resolve(guardrail.execute(input, context));
    const result: GuardrailResult = {
      guardrailName: guardrail.name,
      output,
      passed: !output.tripwireTriggered
    };
    results.push(result);

    if (output.tripwireTriggered) {
      throw new GuardrailTripwireError(guardrail.name, output.outputInfo);
    }
  }

  if (parallelGuardrails.length > 0) {
    const parallelResults = await Promise.all(
      parallelGuardrails.map(async guardrail => {
        const output = await Promise.resolve(guardrail.execute(input, context));
        return {
          guardrailName: guardrail.name,
          output,
          passed: !output.tripwireTriggered
        } satisfies GuardrailResult;
      })
    );

    for (const result of parallelResults) {
      results.push(result);
      if (result.output.tripwireTriggered) {
        throw new GuardrailTripwireError(result.guardrailName, result.output.outputInfo);
      }
    }
  }

  return results;
}

export async function runOutputGuardrails(
  guardrails: OutputGuardrail[],
  output: unknown,
  context?: Record<string, unknown>
): Promise<GuardrailResult[]> {
  const results: GuardrailResult[] = [];

  for (const guardrail of guardrails) {
    const guardrailOutput = await Promise.resolve(guardrail.execute(output, context));
    const result: GuardrailResult = {
      guardrailName: guardrail.name,
      output: guardrailOutput,
      passed: !guardrailOutput.tripwireTriggered
    };
    results.push(result);

    if (guardrailOutput.tripwireTriggered) {
      throw new GuardrailTripwireError(guardrail.name, guardrailOutput.outputInfo);
    }
  }

  return results;
}

export function createContentFilterGuardrail(blockedPatterns: RegExp[]): InputGuardrail {
  return {
    name: 'content_filter',
    runInParallel: true,
    execute: (input) => {
      const text = typeof input === 'string' ? input : JSON.stringify(input);
      for (const pattern of blockedPatterns) {
        if (pattern.test(text)) {
          return {
            tripwireTriggered: true,
            outputInfo: { reason: 'Content blocked by filter', pattern: pattern.source }
          };
        }
      }
      return { tripwireTriggered: false };
    }
  };
}

export function createLengthGuardrail(maxLength: number): InputGuardrail {
  return {
    name: 'length_limit',
    runInParallel: true,
    execute: (input) => {
      const text = typeof input === 'string' ? input : JSON.stringify(input);
      if (text.length > maxLength) {
        return {
          tripwireTriggered: true,
          outputInfo: { reason: 'Input exceeds maximum length', length: text.length, maxLength }
        };
      }
      return { tripwireTriggered: false };
    }
  };
}

export function createOutputSanitizationGuardrail(sensitivePatterns: RegExp[]): OutputGuardrail {
  return {
    name: 'output_sanitization',
    execute: (output) => {
      const text = typeof output === 'string' ? output : JSON.stringify(output);
      for (const pattern of sensitivePatterns) {
        if (pattern.test(text)) {
          return {
            tripwireTriggered: true,
            outputInfo: { reason: 'Output contains sensitive data' }
          };
        }
      }
      return { tripwireTriggered: false };
    }
  };
}
