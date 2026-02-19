import express from 'express';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';

import { config } from './config.js';
import { authenticateRequest, AuthorizationError, REQUIRED_SCOPES, verifyBearerToken } from './auth.js';
import { collectTextFromContent, queryAirfareTrends } from './trends.js';
import { getOpenAIClient } from './openaiClient.js';

import {
  MCPError,
  nonFatalToolError,
  createTransportSecuritySettings,
  transportSecurityMiddleware,
  createProtectedResourceMetadata,
  extractBearerToken,
  oauthErrorResult,
  requireAuth,
  buildToolMeta,
  privateToolMeta,
  DEFAULT_ANNOTATIONS,
  NETWORK_ANNOTATIONS,
  WRITE_ANNOTATIONS,
  MIXED_SECURITY,
  OAUTH_ONLY_SECURITY,
  createStaticToolFilter,
  applyToolFilter,
  detectDuplicateToolNames,
  SessionManager,
  createSessionItem,
  runInputGuardrails,
  runOutputGuardrails,
  createContentFilterGuardrail,
  createLengthGuardrail,
  createOutputSanitizationGuardrail,
  Handoff,
  HandoffRegistry,
  registerWidgetResource,
  widgetUri,
  createWidgetMeta,
  type WidgetDescriptor,
  type InputGuardrail,
  type OutputGuardrail,
  type ToolFilterContext,
  GuardrailTripwireError,
} from './mcp/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const server = new McpServer({
  name: 'mcpkit-advanced',
  version: '1.0.0'
} as any);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));

const transportSecurity = createTransportSecuritySettings();
app.use(transportSecurityMiddleware(transportSecurity));

const auth0IssuerUrl = new URL(config.auth0Issuer);
const authorizationUrl = new URL('authorize', auth0IssuerUrl).toString();
const tokenUrl = new URL('oauth/token', auth0IssuerUrl).toString();
const revocationUrl = new URL('oauth/revoke', auth0IssuerUrl).toString();
const registrationUrl = new URL('oidc/register', auth0IssuerUrl).toString();

const knownClients = new Map<string, { client_id: string; client_secret?: string; redirect_uris: string[]; scope?: string }>();

const oauthProvider = new ProxyOAuthServerProvider({
  endpoints: { authorizationUrl, tokenUrl, revocationUrl, registrationUrl },
  verifyAccessToken: async token => verifyBearerToken(token),
  async getClient(clientId: string) {
    const existing = knownClients.get(clientId);
    if (existing) return existing;
    return {
      client_id: clientId,
      redirect_uris: [
        'https://chatgpt.com/connector_platform_oauth_redirect',
        'https://chatgpt.com/aip/g-callback'
      ],
      scope: REQUIRED_SCOPES.join(' ')
    };
  }
});

oauthProvider.skipLocalPkceValidation = true;

oauthProvider.authorize = async (client, params, res) => {
  const audience = config.expectedAudiences[0] || config.resourceServerUrl.href;
  const targetUrl = new URL(authorizationUrl);
  const searchParams = new URLSearchParams({
    client_id: client.client_id,
    response_type: 'code',
    redirect_uri: params.redirectUri,
    code_challenge: params.codeChallenge,
    code_challenge_method: 'S256',
    audience
  });
  if (params.state) searchParams.set('state', params.state);
  if (params.scopes?.length) searchParams.set('scope', params.scopes.join(' '));
  if (params.resource) searchParams.set('resource', params.resource.href);
  targetUrl.search = searchParams.toString();
  console.info('[auth] redirecting to authorize with audience:', audience);
  res.redirect(targetUrl.toString());
};

const authRouter = mcpAuthRouter({
  provider: oauthProvider,
  issuerUrl: auth0IssuerUrl,
  baseUrl: config.resourceServerUrl,
  scopesSupported: REQUIRED_SCOPES
});

const protectedResourceMetadata = createProtectedResourceMetadata(
  config.resourceServerUrl.href,
  config.auth0Issuer,
  REQUIRED_SCOPES
);

app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  res.json(protectedResourceMetadata);
});

app.options('/.well-known/oauth-protected-resource', (_req, res) => {
  res.status(204).send();
});

app.use((req, res, next) => {
  const originalJson = res.json;
  res.json = function(body: unknown) {
    if (res.statusCode >= 400) {
      console.error(`[auth-debug] ${req.method} ${req.originalUrl} -> ${res.statusCode}`, JSON.stringify(body));
    }
    return originalJson.call(this, body);
  };
  next();
});

app.use((req, _res, next) => {
  if (req.method === 'POST' && req.body?.client_id && req.body?.client_secret) {
    const clientId = req.body.client_id as string;
    const clientSecret = req.body.client_secret as string;
    knownClients.set(clientId, {
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [
        'https://chatgpt.com/connector_platform_oauth_redirect',
        'https://chatgpt.com/aip/g-callback'
      ],
      scope: REQUIRED_SCOPES.join(' ')
    });
  }
  next();
});

app.use(authRouter);

app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(`[error-handler] ${req.method} ${req.originalUrl}`, err.stack || err.message || err);
  if (!res.headersSent) {
    const status = err instanceof MCPError ? err.status : 500;
    res.status(status).json({ error: 'server_error', error_description: err.message });
  }
});

process.on('unhandledRejection', (reason) => {
  console.error('[unhandled-rejection]', reason);
});

const toolFilter = createStaticToolFilter(
  undefined,
  []
);

const sessionManager = new SessionManager({
  trimming: { enabled: true, maxTurns: 100, keepLast: 50 },
  compaction: { enabled: true, triggerTurns: 40, keep: 20 }
});

const inputGuardrails: InputGuardrail[] = [
  createLengthGuardrail(50000),
  createContentFilterGuardrail([])
];

const outputGuardrails: OutputGuardrail[] = [
  createOutputSanitizationGuardrail([])
];

const handoffRegistry = new HandoffRegistry();

handoffRegistry.register(new Handoff(
  { name: 'search_specialist', description: 'Specialist in searching expert call transcripts', handoffDescription: 'Handles deep search queries across transcripts.' },
  { toolNameOverride: 'transfer_to_search_specialist' }
));

handoffRegistry.register(new Handoff(
  { name: 'trends_analyst', description: 'Analyst for airfare trend data', handoffDescription: 'Handles complex trend analysis queries.' },
  { toolNameOverride: 'transfer_to_trends_analyst' }
));

let dashboardHtml: string;
try {
  dashboardHtml = readFileSync(resolve(__dirname, 'widgets', 'dashboard.html'), 'utf-8');
} catch {
  dashboardHtml = '<html><body><p>Dashboard widget</p></body></html>';
}

const dashboardWidget: WidgetDescriptor = {
  id: 'dashboard-widget',
  title: 'Data Dashboard',
  description: 'Interactive dashboard for viewing search results and trend data',
  html: dashboardHtml,
  templateUri: widgetUri('dashboard.html'),
  invoking: 'Loading dashboard...',
  invoked: 'Dashboard ready',
  widgetDomain: config.resourceServerUrl.origin,
  csp: {
    connect_domains: [config.resourceServerUrl.href],
    resource_domains: ['https://cdn.jsdelivr.net']
  },
  prefersBorder: true,
  sessionEnabled: true
};

registerWidgetResource(server, dashboardWidget);

const vectorStoreId = config.vectorStoreId;

const searchMeta = buildToolMeta({
  outputTemplate: dashboardWidget.templateUri,
  invoking: 'Searching transcripts...',
  invoked: 'Search complete',
  widgetAccessible: true,
  securitySchemes: OAUTH_ONLY_SECURITY(REQUIRED_SCOPES)
});

server.registerTool(
  'search',
  {
    title: 'Search Expert Call Transcripts',
    description: 'Semantic search over travel-industry expert call transcripts stored in an OpenAI vector store.',
    inputSchema: {
      query: z.string().describe('Natural language search query. Empty queries return no results.')
    },
    outputSchema: {
      results: z.array(
        z.object({
          id: z.string(),
          title: z.string(),
          text: z.string(),
          url: z.string()
        })
      )
    },
    _meta: searchMeta,
    annotations: NETWORK_ANNOTATIONS
  },
  async ({ query }) => {
    try {
      await runInputGuardrails(inputGuardrails, query);

      const trimmedQuery = query.trim();
      if (!trimmedQuery) {
        const empty = { results: [] as Array<{ id: string; title: string; text: string; url: string }> };
        return { content: [{ type: 'text', text: JSON.stringify(empty) }], structuredContent: empty };
      }

      if (!vectorStoreId) {
        return nonFatalToolError(new Error('Vector store not configured. Set VECTOR_STORE_ID.'), 'search');
      }

      const openai = getOpenAIClient();
      const response = await openai.vectorStores.search(vectorStoreId, {
        query: trimmedQuery,
        ranking_options: { score_threshold: 0.5 },
        rewrite_query: true
      } as any);

      const data = Array.isArray((response as any).data)
        ? ((response as any).data as Array<Record<string, unknown>>)
        : [];

      const results = data.map((item, index) => {
        const rawContent = item['content'];
        const text = collectTextFromContent(rawContent);
        const snippet = text.length > 200 ? `${text.slice(0, 200)}...` : text || 'No content available';
        const id = String(item['file_id'] ?? item['id'] ?? `vs_${index}`);
        const title = String(item['filename'] ?? `Document ${index + 1}`);
        return { id, title, text: snippet, url: `https://platform.openai.com/storage/files/${id}` };
      });

      const payload = { results };

      await runOutputGuardrails(outputGuardrails, payload);

      return {
        content: [{ type: 'text', text: JSON.stringify(payload) }],
        structuredContent: payload,
        _meta: searchMeta
      };
    } catch (error) {
      if (error instanceof GuardrailTripwireError) {
        return { isError: true, content: [{ type: 'text', text: `Blocked: ${error.message}` }] };
      }
      return nonFatalToolError(error, 'search');
    }
  }
);

const fetchMeta = buildToolMeta({
  invoking: 'Fetching transcript...',
  invoked: 'Transcript retrieved',
  securitySchemes: OAUTH_ONLY_SECURITY(REQUIRED_SCOPES)
});

server.registerTool(
  'fetch',
  {
    title: 'Fetch Transcript',
    description: 'Retrieve the full expert-call transcript text for a given file ID.',
    inputSchema: {
      id: z.string().describe('File ID returned from the search tool.')
    },
    _meta: fetchMeta,
    annotations: NETWORK_ANNOTATIONS
  },
  async ({ id }) => {
    try {
      if (!vectorStoreId) {
        return nonFatalToolError(new Error('Vector store not configured.'), 'fetch');
      }

      const openai = getOpenAIClient();
      const contentResponse = await openai.vectorStores.files.content(id, { vector_store_id: vectorStoreId });
      const data = (contentResponse as any)?.data ?? contentResponse;
      const text = collectTextFromContent(data);

      let title = `Document ${id}`;
      let metadata: Record<string, unknown> | undefined;

      try {
        const fileInfo = await openai.vectorStores.files.retrieve(id, { vector_store_id: vectorStoreId });
        const record = fileInfo as any;
        if (typeof record.filename === 'string') title = record.filename;
        if (record.attributes && typeof record.attributes === 'object') metadata = record.attributes as Record<string, unknown>;
      } catch (infoError) {
        console.warn('Failed to fetch vector store file metadata:', infoError);
      }

      const payload = { id, title, text: text || 'No content available.', url: `https://platform.openai.com/storage/files/${id}`, metadata };
      return {
        content: [{ type: 'text', text: JSON.stringify(payload) }],
        structuredContent: payload,
        _meta: fetchMeta
      };
    } catch (error) {
      return nonFatalToolError(error, 'fetch');
    }
  }
);

const trendsMeta = buildToolMeta({
  outputTemplate: dashboardWidget.templateUri,
  invoking: 'Analyzing airfare trends...',
  invoked: 'Trend analysis complete',
  widgetAccessible: true,
  securitySchemes: MIXED_SECURITY(REQUIRED_SCOPES)
});

server.registerTool(
  'airfare_trend_insights',
  {
    title: 'Airfare Trend Insights',
    description: 'Filter structured airfare pricing and demand trend snapshots from local CSV/TSV/JSON files.',
    inputSchema: {
      snapshotDate: z.string().describe('Exact snapshot date (YYYY-MM-DD)').optional(),
      routeContains: z.string().describe('Substring to match against the route column.').optional(),
      originAirport: z.string().describe('Exact origin airport code.').optional(),
      destinationAirport: z.string().describe('Exact destination airport code.').optional(),
      airlineContains: z.string().describe('Substring to match airlines.').optional(),
      seasonContains: z.string().describe('Substring to match season.').optional(),
      notableContains: z.string().describe('Substring match against notable_event.').optional(),
      limit: z.number().int().min(1).max(200).describe('Maximum number of rows to return (default 25).').optional()
    },
    outputSchema: {
      rows: z.array(z.record(z.any())),
      available_files: z.array(z.string()),
      filters: z.record(z.any()),
      total_rows: z.number(),
      matched_rows: z.number(),
      rows_returned: z.number(),
      trend_data_dir: z.string()
    },
    _meta: trendsMeta,
    annotations: DEFAULT_ANNOTATIONS
  },
  async input => {
    try {
      const payload = await queryAirfareTrends(config.trendDataDir, {
        snapshotDate: input.snapshotDate ?? null,
        routeContains: input.routeContains ?? null,
        originAirport: input.originAirport ?? null,
        destinationAirport: input.destinationAirport ?? null,
        airlineContains: input.airlineContains ?? null,
        seasonContains: input.seasonContains ?? null,
        notableContains: input.notableContains ?? null,
        limit: input.limit ?? null
      });

      return {
        content: [{ type: 'text', text: JSON.stringify(payload) }],
        structuredContent: payload,
        _meta: trendsMeta
      };
    } catch (error) {
      return nonFatalToolError(error, 'airfare_trend_insights');
    }
  }
);

const dashboardMeta = buildToolMeta({
  outputTemplate: dashboardWidget.templateUri,
  invoking: 'Opening dashboard...',
  invoked: 'Dashboard loaded',
  widgetAccessible: true,
  securitySchemes: MIXED_SECURITY(REQUIRED_SCOPES)
});

server.registerTool(
  'open_dashboard',
  {
    title: 'Open Data Dashboard',
    description: 'Launch the interactive data dashboard widget for visualizing search results and trend data.',
    inputSchema: {
      view: z.enum(['trends', 'search', 'overview']).describe('Which view to show in the dashboard').optional()
    },
    _meta: dashboardMeta,
    annotations: DEFAULT_ANNOTATIONS
  },
  async ({ view }) => {
    const selectedView = view ?? 'overview';
    const payload = { dashboard: true, view: selectedView, toolCount: 8, widgetCount: 1, sessionCount: sessionManager.listSessionIds().length, status: 'ready', message: `Dashboard loaded in ${selectedView} view` };
    return {
      content: [{ type: 'text', text: `Dashboard opened in ${selectedView} view.` }],
      structuredContent: payload,
      _meta: dashboardMeta
    };
  }
);

const widgetCallbackMeta = privateToolMeta({
  outputTemplate: dashboardWidget.templateUri,
  widgetAccessible: true
});

server.registerTool(
  'widget_update_session',
  {
    title: 'Update Widget Session',
    description: 'Internal widget hook: update session data from widget interactions.',
    inputSchema: {
      sessionId: z.string().describe('Widget session ID'),
      action: z.string().describe('Action performed in the widget'),
      data: z.record(z.any()).describe('Action data').optional()
    },
    _meta: widgetCallbackMeta,
    annotations: WRITE_ANNOTATIONS
  },
  async ({ sessionId, action, data }) => {
    try {
      const session = sessionManager.getOrCreate(sessionId);
      session.addItems([createSessionItem('system', `Widget action: ${action}`, data)]);

      return {
        content: [{ type: 'text', text: `Session ${sessionId} updated with action: ${action}` }],
        structuredContent: { sessionId, action, itemCount: session.getItems().length }
      };
    } catch (error) {
      return nonFatalToolError(error, 'widget_update_session');
    }
  }
);

server.registerTool(
  'manage_session',
  {
    title: 'Manage Conversation Session',
    description: 'Create, retrieve, or clear conversation sessions for persistent memory across tool calls.',
    inputSchema: {
      action: z.enum(['create', 'get', 'clear', 'list']).describe('Session management action'),
      sessionId: z.string().describe('Session ID (optional for create/list)').optional()
    },
    _meta: buildToolMeta({
      invoking: 'Managing session...',
      invoked: 'Session updated',
      securitySchemes: MIXED_SECURITY(REQUIRED_SCOPES)
    }),
    annotations: WRITE_ANNOTATIONS
  },
  async ({ action, sessionId }) => {
    try {
      switch (action) {
        case 'create': {
          const id = sessionId ?? `session_${Date.now()}`;
          const session = sessionManager.getOrCreate(id);
          return {
            content: [{ type: 'text', text: `Session ${id} created.` }],
            structuredContent: { sessionId: session.getSessionId(), action: 'created' }
          };
        }
        case 'get': {
          if (!sessionId) {
            return nonFatalToolError(new Error('sessionId required for get action'), 'manage_session');
          }
          const session = sessionManager.get(sessionId);
          if (!session) {
            return { content: [{ type: 'text', text: `Session ${sessionId} not found.` }], structuredContent: { error: 'not_found' } };
          }
          const items = session.getItems();
          return {
            content: [{ type: 'text', text: `Session ${sessionId}: ${items.length} items.` }],
            structuredContent: { sessionId, items, itemCount: items.length }
          };
        }
        case 'clear': {
          if (!sessionId) {
            return nonFatalToolError(new Error('sessionId required for clear action'), 'manage_session');
          }
          sessionManager.delete(sessionId);
          return {
            content: [{ type: 'text', text: `Session ${sessionId} cleared.` }],
            structuredContent: { sessionId, action: 'cleared' }
          };
        }
        case 'list': {
          const ids = sessionManager.listSessionIds();
          return {
            content: [{ type: 'text', text: `Active sessions: ${ids.length}` }],
            structuredContent: { sessions: ids, count: ids.length }
          };
        }
      }
    } catch (error) {
      return nonFatalToolError(error, 'manage_session');
    }
  }
);

for (const handoff of handoffRegistry.list()) {
  const handoffMeta = buildToolMeta({
    invoking: `Transferring to ${handoff.agentName}...`,
    invoked: `Connected to ${handoff.agentName}`,
    securitySchemes: MIXED_SECURITY(REQUIRED_SCOPES)
  });

  server.registerTool(
    handoff.toolName,
    {
      title: `Transfer to ${handoff.agent.name}`,
      description: handoff.toolDescription,
      inputSchema: {
        reason: z.string().describe('Reason for the handoff')
      },
      _meta: handoffMeta,
      annotations: DEFAULT_ANNOTATIONS
    },
    async ({ reason }) => {
      try {
        const result = await handoff.invoke({ reason });
        return {
          content: [{ type: 'text', text: `Transferred to ${result.agent.name}. ${result.agent.description ?? ''}` }],
          structuredContent: {
            handoff: true,
            agent: result.agent.name,
            reason,
            transferMessage: result.transferMessage
          }
        };
      } catch (error) {
        return nonFatalToolError(error, handoff.toolName);
      }
    }
  );
}

app.options('/mcp', (_req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id');
  res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
  res.status(204).send();
});

app.post('/mcp', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');

    const authInfo = await authenticateRequest(req);

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });

    await server.connect(transport);

    (req as typeof req & { auth: typeof authInfo }).auth = authInfo;

    res.on('close', () => {
      transport.close().catch(err => console.error('Transport close error', err));
    });

    await transport.handleRequest(req as typeof req & { auth: typeof authInfo }, res, req.body);
  } catch (error) {
    if (error instanceof AuthorizationError) {
      res.status(error.status).json({
        jsonrpc: '2.0',
        error: { code: error.status, message: error.message },
        id: null
      });
      return;
    }
    console.error('Unhandled MCP request error', error);
    res.status(500).json({
      jsonrpc: '2.0',
      error: { code: -32603, message: 'Internal server error' },
      id: null
    });
  }
});

async function logStartupInfo() {
  console.info('[auth] issuer:', auth0IssuerUrl.href);
  console.info('[auth] authorization endpoint:', authorizationUrl);
  console.info('[auth] token endpoint:', tokenUrl);
  console.info('[auth] revocation endpoint:', revocationUrl);
  console.info('[auth] registration endpoint:', registrationUrl);
  console.info('[auth] required scopes:', REQUIRED_SCOPES.join(', ') || '(none)');
  console.info('[transport] DNS rebinding protection:', transportSecurity.enableDnsRebindingProtection);
  console.info('[widgets] dashboard registered at:', dashboardWidget.templateUri);
  console.info('[handoffs] registered:', handoffRegistry.list().map(h => h.toolName).join(', '));
  console.info('[sessions] memory strategies: trimming=enabled, compaction=enabled');
  console.info('[guardrails] input:', inputGuardrails.length, '| output:', outputGuardrails.length);

  const toolNames = ['search', 'fetch', 'airfare_trend_insights', 'open_dashboard', 'widget_update_session', 'manage_session'];
  for (const h of handoffRegistry.list()) toolNames.push(h.toolName);
  const duplicates = detectDuplicateToolNames(toolNames);
  if (duplicates.length > 0) {
    console.error('[tools] DUPLICATE TOOL NAMES DETECTED:', duplicates.join(', '));
  }

  let blockedCount = 0;
  for (const name of toolNames) {
    const ctx: ToolFilterContext = { toolName: name, serverName: 'mcpkit-advanced' };
    const allowed = await applyToolFilter(toolFilter, ctx);
    if (!allowed) blockedCount++;
  }
  console.info('[tools] registered:', toolNames.length, 'tools (no duplicates)',
    blockedCount > 0 ? `| ${blockedCount} filtered out` : '| filter: pass-through');
}

logStartupInfo();

const serverInstance = app.listen(config.port, () => {
  console.info(`MCP server listening on ${config.resourceServerUrl.href}`);
});

process.on('SIGINT', () => {
  console.info('Received SIGINT, shutting down');
  serverInstance.close(() => process.exit(0));
});

process.on('SIGTERM', () => {
  console.info('Received SIGTERM, shutting down');
  serverInstance.close(() => process.exit(0));
});
