export interface ToolAnnotations {
  [key: string]: unknown;
  destructiveHint?: boolean;
  readOnlyHint?: boolean;
  openWorldHint?: boolean;
  idempotentHint?: boolean;
}

export interface ToolMetaConfig {
  outputTemplate?: string;
  invoking?: string;
  invoked?: string;
  widgetAccessible?: boolean;
  widgetSessionId?: string;
  widgetCSP?: Record<string, string[]>;
  widgetPrefersBorder?: boolean;
  visibility?: 'private' | 'public';
  securitySchemes?: SecurityScheme[];
}

export interface SecurityScheme {
  type: 'noauth' | 'oauth2';
  scopes?: string[];
}

export const NOAUTH_SCHEME: SecurityScheme = { type: 'noauth' };
export const OAUTH2_SCHEME = (scopes: string[]): SecurityScheme => ({
  type: 'oauth2',
  scopes
});

export const MIXED_SECURITY = (scopes: string[]): SecurityScheme[] => [
  NOAUTH_SCHEME,
  OAUTH2_SCHEME(scopes)
];

export const OAUTH_ONLY_SECURITY = (scopes: string[]): SecurityScheme[] => [
  OAUTH2_SCHEME(scopes)
];

export function buildToolMeta(config: ToolMetaConfig): Record<string, unknown> {
  const meta: Record<string, unknown> = {};

  if (config.outputTemplate) {
    meta['openai/outputTemplate'] = config.outputTemplate;
  }
  if (config.invoking) {
    meta['openai/toolInvocation/invoking'] = config.invoking;
  }
  if (config.invoked) {
    meta['openai/toolInvocation/invoked'] = config.invoked;
  }
  if (config.widgetAccessible !== undefined) {
    meta['openai/widgetAccessible'] = config.widgetAccessible;
  }
  if (config.widgetSessionId) {
    meta['openai/widgetSessionId'] = config.widgetSessionId;
  }
  if (config.widgetCSP) {
    meta['openai/widgetCSP'] = config.widgetCSP;
  }
  if (config.widgetPrefersBorder !== undefined) {
    meta['openai/widgetPrefersBorder'] = config.widgetPrefersBorder;
  }
  if (config.visibility) {
    meta['openai/visibility'] = config.visibility;
  }
  if (config.securitySchemes) {
    meta['securitySchemes'] = config.securitySchemes;
  }

  return meta;
}

export function privateToolMeta(config: Omit<ToolMetaConfig, 'visibility'>): Record<string, unknown> {
  return buildToolMeta({ ...config, visibility: 'private' });
}

export function publicToolMeta(config: Omit<ToolMetaConfig, 'visibility'>): Record<string, unknown> {
  return buildToolMeta({ ...config, visibility: 'public' });
}

export const DEFAULT_ANNOTATIONS: ToolAnnotations = {
  destructiveHint: false,
  readOnlyHint: true,
  openWorldHint: false
};

export const WRITE_ANNOTATIONS: ToolAnnotations = {
  destructiveHint: false,
  readOnlyHint: false,
  openWorldHint: false
};

export const DESTRUCTIVE_ANNOTATIONS: ToolAnnotations = {
  destructiveHint: true,
  readOnlyHint: false,
  openWorldHint: false
};

export const NETWORK_ANNOTATIONS: ToolAnnotations = {
  destructiveHint: false,
  readOnlyHint: true,
  openWorldHint: true
};
