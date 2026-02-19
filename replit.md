# MCPKit: Advanced MCP Server with Enterprise Patterns

## Overview
MCPKit is an advanced, production-ready Model Context Protocol (MCP) server implementing patterns from OpenAI's SDK ecosystem. It brings proprietary data into ChatGPT via Dev Mode with widgets, guardrails, handoffs, session management, tool filtering, and mixed auth.

## Project Architecture

### Directory Structure
```
/
├── typescript-authenticated-mcp-server-scaffold/   # TypeScript MCP server (Express)
│   ├── src/
│   │   ├── server.ts          # Main Express server with modular registration pipeline
│   │   ├── config.ts          # Environment config with Zod validation
│   │   ├── auth.ts            # JWT/OAuth token verification (Auth0)
│   │   ├── openaiClient.ts    # OpenAI client singleton
│   │   ├── trends.ts          # Airfare trend data loading and querying
│   │   ├── mcp/               # Advanced MCP pattern modules
│   │   │   ├── index.ts       # Barrel export for all modules
│   │   │   ├── errors.ts      # Hierarchical error classes (MCPError → specific types)
│   │   │   ├── transport.ts   # Transport security (DNS rebinding, allowed hosts/origins)
│   │   │   ├── widgets.ts     # Widget system (skybridge MIME, ui:// URIs, CSP, sessions)
│   │   │   ├── toolMeta.ts    # Tool _meta fields, annotations, security schemes
│   │   │   ├── toolFilter.ts  # Static/dynamic tool filtering, duplicate detection
│   │   │   ├── mcpAuth.ts     # Mixed auth, bearer extraction, RFC 9728, www_authenticate
│   │   │   ├── session.ts     # Session/memory management (trimming, compaction)
│   │   │   ├── guardrails.ts  # Input/output guardrails with tripwire triggering
│   │   │   └── handoffs.ts    # Agent handoffs (transfer_to naming, input filters)
│   │   └── widgets/
│   │       └── dashboard.html # Interactive dashboard widget (skybridge)
│   ├── package.json
│   └── tsconfig.json
├── python-authenticated-mcp-server-scaffold/       # Python MCP server (FastAPI/Uvicorn)
├── synthetic_financial_data/                       # Sample data for demos
├── _analysis/
│   └── PATTERNS.md            # Comprehensive pattern analysis from OpenAI repos
└── scripts/
    └── upload_expert_calls_to_vector_store.py
```

### Key Technologies
- **TypeScript Server**: Express, MCP SDK, Zod, jose (JWT), OpenAI SDK, tsx
- **Auth**: Auth0 (or any OIDC provider) with OAuth 2.1 + PKCE
- **Patterns**: Widget system, guardrails, handoffs, sessions, tool filtering, mixed auth

### Environment Variables
- `PORT` - Server port (default: 5000)
- `AUTH0_ISSUER` - Auth0 tenant URL
- `OPENAI_API_KEY` - OpenAI API key for vector store search
- `VECTOR_STORE_ID` - OpenAI Vector Store ID for transcript search
- `RESOURCE_SERVER_URL` - Public URL of the MCP server
- `JWT_AUDIENCES` - Comma-separated OAuth audiences
- `MCP_ALLOWED_HOSTS` - Comma-separated allowed hosts for transport security
- `MCP_ALLOWED_ORIGINS` - Comma-separated allowed origins for transport security

### MCP Tools (8 total)
1. **search** - Semantic search over expert call transcripts (with widget, guardrails)
2. **fetch** - Retrieve full transcript by file ID
3. **airfare_trend_insights** - Query structured airfare pricing/demand data (with widget)
4. **open_dashboard** - Launch interactive dashboard widget
5. **widget_update_session** - Private widget-only tool for session updates
6. **manage_session** - Create/get/clear/list conversation sessions
7. **transfer_to_search_specialist** - Handoff to search specialist agent
8. **transfer_to_trends_analyst** - Handoff to trends analyst agent

### Advanced Patterns Implemented
- **Widget System**: HTML widgets via `text/html+skybridge` MIME, `ui://widget/` URI scheme, CSP config
- **Tool _meta Fields**: outputTemplate, toolInvocation/invoking|invoked, widgetAccessible, widgetSessionId, visibility
- **Private Tools**: `openai/visibility: "private"` hides tools from model (widget-only)
- **Mixed Auth**: `securitySchemes` with `noauth` + `oauth2` per-tool
- **RFC 9728**: `/.well-known/oauth-protected-resource` endpoint
- **Bearer Token Extraction**: From request headers for per-tool auth gating
- **OAuth Error Responses**: `mcp/www_authenticate` in _meta triggers OAuth flow
- **Tool Annotations**: destructiveHint, readOnlyHint, openWorldHint per tool
- **Session Management**: In-memory sessions with trimming + compaction strategies
- **Guardrails**: Input (length, content filter) + output (sanitization) with tripwire
- **Handoffs**: transfer_to_{agent} naming, input filters, conditional enablement
- **Tool Filtering**: Static allowlist/blocklist + dynamic callable filters
- **Transport Security**: DNS rebinding protection, allowed hosts/origins
- **Non-Fatal Errors**: Tool errors become model-visible messages, hierarchical error classes
- **Structured Content**: content + structuredContent on all tool responses

### Running
- **TypeScript**: `cd typescript-authenticated-mcp-server-scaffold && npm run dev` (port 5000)

## Recent Changes
- 2026-02-19: Major rebuild with all advanced OpenAI SDK patterns
  - Added modular MCP pattern modules (errors, transport, widgets, toolMeta, toolFilter, mcpAuth, session, guardrails, handoffs)
  - Implemented widget system with dashboard HTML widget
  - Added 8 tools with full _meta, annotations, and structured content
  - Implemented session management with trimming and compaction
  - Added input/output guardrails with tripwire triggering
  - Added agent handoff system with transfer_to naming
  - Added RFC 9728 protected resource metadata endpoint
  - Added mixed auth security schemes per-tool
  - Fixed Auth0 JWT token exchange (audience parameter)
  - Fixed client_secret forwarding for token exchange

## User Preferences
- None recorded yet
