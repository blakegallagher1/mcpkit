import type { Request } from 'express';

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported: string[];
  bearer_methods_supported?: string[];
  resource_documentation?: string;
}

export function createProtectedResourceMetadata(
  resourceUrl: string,
  authorizationServerUrl: string,
  scopes: string[]
): ProtectedResourceMetadata {
  return {
    resource: resourceUrl,
    authorization_servers: [authorizationServerUrl],
    scopes_supported: scopes,
    bearer_methods_supported: ['header']
  };
}

export function extractBearerToken(req: Request): string | null {
  const header = req.headers['authorization'] ?? req.headers['Authorization'];
  if (!header || Array.isArray(header)) return null;

  const trimmed = header.trim();
  if (!trimmed.toLowerCase().startsWith('bearer ')) return null;

  const token = trimmed.slice('bearer '.length).trim();
  return token || null;
}

export function extractBearerTokenFromHeaders(headers: Record<string, string | string[] | undefined>): string | null {
  const header = headers['authorization'] ?? headers['Authorization'];
  if (!header) return null;
  const value = Array.isArray(header) ? header[0] : header;
  if (!value) return null;

  const trimmed = value.trim();
  if (!trimmed.toLowerCase().startsWith('bearer ')) return null;

  const token = trimmed.slice('bearer '.length).trim();
  return token || null;
}

export function buildWwwAuthenticateValue(
  error: string,
  description: string,
  realm?: string
): string {
  const parts = [`Bearer realm="${realm ?? 'mcp'}"`];
  parts.push(`error="${error}"`);
  parts.push(`error_description="${description}"`);
  return parts.join(', ');
}

export function oauthErrorResult(
  userMessage: string,
  options: {
    error?: string;
    description?: string;
    realm?: string;
  } = {}
) {
  const error = options.error ?? 'invalid_request';
  const description = options.description ?? userMessage;

  return {
    isError: true as const,
    content: [{ type: 'text' as const, text: userMessage }],
    _meta: {
      'mcp/www_authenticate': [
        buildWwwAuthenticateValue(error, description, options.realm)
      ]
    }
  };
}

export function requireAuth(token: string | null, toolName: string) {
  if (!token) {
    return oauthErrorResult(
      `Authentication required to use ${toolName}. Please sign in.`,
      {
        error: 'invalid_token',
        description: 'No access token was provided'
      }
    );
  }
  return null;
}
