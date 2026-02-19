# OpenAI SDK Ecosystem — Advanced Patterns Analysis

> Comprehensive analysis of architecture, MCP/tool, auth, streaming, agent, UI, error handling, and type patterns extracted from 9 OpenAI repositories.

---

## Table of Contents

1. [MCP/Tool Patterns](#1-mcptool-patterns)
2. [Widget & ChatGPT App Patterns](#2-widget--chatgpt-app-patterns)
3. [OAuth/Auth Patterns](#3-oauthauth-patterns)
4. [Streaming & Transport Patterns](#4-streaming--transport-patterns)
5. [Agent Orchestration Patterns](#5-agent-orchestration-patterns)
6. [Guardrail Patterns](#6-guardrail-patterns)
7. [Handoff Patterns](#7-handoff-patterns)
8. [Memory & Session Patterns](#8-memory--session-patterns)
9. [Error Handling Patterns](#9-error-handling-patterns)
10. [Architecture & Dependency Patterns](#10-architecture--dependency-patterns)
11. [TypeScript/Python Type Patterns](#11-typescriptpython-type-patterns)
12. [UI/Component Patterns](#12-uicomponent-patterns)
13. [ChatKit Server Patterns](#13-chatkit-server-patterns)
14. [Tool Filtering Patterns](#14-tool-filtering-patterns)

---

## 1. MCP/Tool Patterns

### 1.1 Tool Definition with `_meta` Fields (from `openai-apps-sdk-examples`)

Every MCP tool exposed to ChatGPT uses `_meta` fields to control widget rendering and UX messaging. This is the fundamental pattern for ChatGPT app connectors.

```typescript
// From pizzaz_server_node/src/server.ts
function widgetDescriptorMeta(widget: PizzazWidget) {
  return {
    "openai/outputTemplate": widget.templateUri,       // Links tool to widget HTML
    "openai/toolInvocation/invoking": widget.invoking,  // Loading message
    "openai/toolInvocation/invoked": widget.invoked,    // Completion message
    "openai/widgetAccessible": true,                    // Widget can call tools
  } as const;
}

const tools: Tool[] = widgets.map((widget) => ({
  name: widget.id,
  description: widget.title,
  inputSchema: toolInputSchema,
  title: widget.title,
  _meta: widgetDescriptorMeta(widget),
  annotations: {
    destructiveHint: false,    // No destructive side effects
    openWorldHint: false,      // No external network calls
    readOnlyHint: true,        // Read-only operation
  },
}));
```

**Key `_meta` fields:**
| Field | Purpose |
|-------|---------|
| `openai/outputTemplate` | URI linking tool to its widget HTML (e.g., `ui://widget/pizza-map.html`) |
| `openai/toolInvocation/invoking` | Loading text shown while tool executes |
| `openai/toolInvocation/invoked` | Completion text shown after tool finishes |
| `openai/widgetAccessible` | Whether the widget can invoke tools back |
| `openai/widgetSessionId` | Session ID for widget state persistence |
| `openai/widgetPrefersBorder` | Whether widget should have a border |
| `openai/widgetCSP` | Content Security Policy for the widget |
| `openai/visibility` | Tool visibility (`"private"` hides from model) |
| `securitySchemes` | OAuth security requirements for the tool |

### 1.2 Tool Registration with Low-Level MCP Server (Python)

```python
# From shopping_cart_python/main.py
mcp = FastMCP(
    name="ecommerce-python",
    stateless_http=True,
    transport_security=_transport_security_settings(),
)

# Low-level handler registration (bypasses FastMCP decorators)
@mcp._mcp_server.list_tools()
async def _list_tools() -> List[types.Tool]:
    return [
        types.Tool(
            name=TOOL_NAME,
            title="Add items to cart",
            description="Adds items to the active cart and returns its state.",
            inputSchema=TOOL_INPUT_SCHEMA,
            _meta=_widget_meta(),
        )
    ]

# Direct request handler override
mcp._mcp_server.request_handlers[types.CallToolRequest] = _handle_call_tool
mcp._mcp_server.request_handlers[types.ReadResourceRequest] = _handle_read_resource
```

### 1.3 Tool Registration with High-Level McpServer (Node.js)

```javascript
// From build-hours/22-chatgptapp-pingpong/server.js
const server = new McpServer({ name: "pingpong-app", version: "0.1.0" });

server.registerResource(
  "pingpong-widget",
  "ui://widget/pingpong.html",
  {},
  async () => ({
    contents: [{
      uri: "ui://widget/pingpong.html",
      mimeType: "text/html+skybridge",  // Critical MIME type for widgets
      text: pingpongHtml,
      _meta: {
        "openai/widgetPrefersBorder": false,
        "openai/widgetCSP": widgetCsp,
      },
    }],
  })
);

server.registerTool(
  "launch_game",
  {
    title: "Launch Ping Pong",
    description: "Open the Ping Pong widget",
    inputSchema: launchGameInputSchema,  // Zod schema
    _meta: {
      "openai/outputTemplate": "ui://widget/pingpong.html",
      "openai/toolInvocation/invoking": "Launching Ping Pong",
      "openai/toolInvocation/invoked": "Ping Pong ready",
    },
  },
  async (args) => ({
    content: [{ type: "text", text: `Ping Pong ready. Difficulty: ${args.difficulty}.` }],
    structuredContent: { difficulty: args.difficulty },
    _meta: toolMeta,
  })
);
```

### 1.4 Structured Content Response Pattern

Tools return both `content` (text for the model) and `structuredContent` (JSON for widgets):

```python
# From shopping_cart_python/main.py
structured_content = {
    "cartId": cart_id,
    "items": [dict(item) for item in cart_items],
}
meta = _widget_meta()
meta["openai/widgetSessionId"] = cart_id  # Session binding

return types.ServerResult(
    types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        structuredContent=structured_content,  # JSON for widget
        _meta=meta,
    )
)
```

### 1.5 Private/Widget-Only Tools Pattern

Tools can be marked private so only widgets (not the model) can invoke them:

```javascript
// From build-hours/22-chatgptapp-pingpong/server.js
server.registerTool("report_game_stats", {
  title: "Report Ping Pong stats",
  description: "Internal widget hook: report current match stats",
  inputSchema: reportGameStatsInputSchema,
  _meta: {
    "openai/outputTemplate": "ui://widget/pingpong.html",
    "openai/widgetAccessible": true,
    "openai/visibility": "private",  // Hidden from the model
  },
  annotations: {
    readOnlyHint: false,
    openWorldHint: false,
    destructiveHint: false,
  },
});
```

### 1.6 MCP Tool-to-FunctionTool Conversion (Agents SDK)

The Agents SDK converts MCP tools to its internal `FunctionTool` format:

```python
# From openai-agents-python/src/agents/mcp/util.py
@classmethod
def to_function_tool(cls, tool, server, convert_schemas_to_strict, agent=None,
                     failure_error_function=default_tool_error_function) -> FunctionTool:
    schema, is_strict = tool.inputSchema, False

    # MCP spec doesn't require properties, but OpenAI spec does
    if "properties" not in schema:
        schema["properties"] = {}

    if convert_schemas_to_strict:
        try:
            schema = ensure_strict_json_schema(schema)
            is_strict = True
        except Exception as e:
            logger.info(f"Error converting MCP schema to strict mode: {e}")

    # Wrap invoke with error handling
    async def invoke_func(ctx, input_json):
        try:
            return await invoke_func_impl(ctx, input_json)
        except Exception as e:
            if effective_failure_error_function is None:
                raise
            result = effective_failure_error_function(ctx, e)
            if inspect.isawaitable(result):
                result = await result
            _error_tracing.attach_error_to_current_span(
                SpanError(message="Error running tool (non-fatal)", data={"tool_name": tool.name})
            )
            return result

    return FunctionTool(
        name=tool.name,
        description=tool.description or "",
        params_json_schema=schema,
        on_invoke_tool=invoke_func,
        strict_json_schema=is_strict,
        needs_approval=server._get_needs_approval_for_tool(tool, agent),
    )
```

### 1.7 MCP Meta Resolver Pattern

Dynamic metadata injection at tool invocation time:

```python
# From openai-agents-python/src/agents/mcp/util.py
@classmethod
async def _resolve_meta(cls, server, context, tool_name, arguments):
    meta_resolver = getattr(server, "tool_meta_resolver", None)
    if meta_resolver is None:
        return None

    arguments_copy = copy.deepcopy(arguments)  # Defensive copy
    resolver_context = MCPToolMetaContext(
        run_context=context,
        server_name=server.name,
        tool_name=tool_name,
        arguments=arguments_copy,
    )
    result = meta_resolver(resolver_context)
    if inspect.isawaitable(result):
        result = await result
    return result

# Merge resolved + explicit meta
@staticmethod
def _merge_mcp_meta(resolved_meta, explicit_meta):
    if resolved_meta is None and explicit_meta is None:
        return None
    merged = {}
    if resolved_meta is not None:
        merged.update(resolved_meta)
    if explicit_meta is not None:
        merged.update(explicit_meta)  # Explicit wins
    return merged
```

---

## 2. Widget & ChatGPT App Patterns

### 2.1 Widget HTML as Resources

Widgets use the `text/html+skybridge` MIME type and `ui://widget/` URI scheme:

```python
# Resource registration
types.Resource(
    name=WIDGET_TITLE,
    title=WIDGET_TITLE,
    uri="ui://widget/shopping-cart.html",
    description="Markup for the shopping cart widget.",
    mimeType="text/html+skybridge",
    _meta=_widget_meta(),
)
```

### 2.2 Widget Content Security Policy

```javascript
// From build-hours/22-chatgptapp-pingpong/server.js
const widgetCsp = {
  connect_domains: [
    "wss://liveblocks.io", "wss://*.liveblocks.io",
    "https://unpkg.com", "https://cdn.jsdelivr.net",
    appBaseUrl,
  ].filter(Boolean),
  resource_domains: [
    "https://unpkg.com", "https://cdn.jsdelivr.net",
    "https://fonts.googleapis.com", "https://fonts.gstatic.com",
    appBaseUrl,
  ],
};
```

### 2.3 Widget Diffing/Streaming Pattern (ChatKit)

```python
# From chatkit-python/chatkit/server.py
def diff_widget(before: WidgetRoot, after: WidgetRoot):
    """Compare two WidgetRoots and return a list of deltas."""
    
    def is_streaming_text(component):
        return getattr(component, "type", None) in {"Markdown", "Text"} \
               and isinstance(getattr(component, "value", None), str)

    def full_replace(before, after):
        if before.type != after.type or before.id != after.id or before.key != after.key:
            return True
        # Check all fields for changes, except streaming text appends
        for field in before.model_fields_set.union(after.model_fields_set):
            if is_streaming_text(before) and is_streaming_text(after) and field == "value":
                if getattr(after, "value", "").startswith(getattr(before, "value", "")):
                    continue  # Appends don't trigger full replace
            if full_replace_value(getattr(before, field), getattr(after, field)):
                return True
        return False

    # Streaming text gets incremental deltas
    deltas = []
    for id, after_node in after_nodes.items():
        before_value = str(getattr(before_nodes[id], "value", None))
        after_value = str(getattr(after_node, "value", None))
        if before_value != after_value:
            deltas.append(WidgetStreamingTextValueDelta(
                component_id=id,
                delta=after_value[len(before_value):],
                done=not getattr(after_node, "streaming", False),
            ))
    return deltas
```

### 2.4 Widget Streaming via AsyncGenerator

```python
# From chatkit-python/chatkit/server.py
async def stream_widget(thread, widget, copy_text=None, generate_id=default_generate_id):
    """Stream a widget root (or async sequence of roots) as ThreadStreamEvents."""
    item_id = generate_id("message")

    if not isinstance(widget, AsyncGenerator):
        yield ThreadItemDoneEvent(item=WidgetItem(..., widget=widget))
        return

    initial_state = await widget.__anext__()
    yield ThreadItemAddedEvent(item=WidgetItem(..., widget=initial_state))

    last_state = initial_state
    while widget:
        try:
            new_state = await widget.__anext__()
            for update in diff_widget(last_state, new_state):
                yield ThreadItemUpdatedEvent(item_id=item_id, update=update)
            last_state = new_state
        except StopAsyncIteration:
            break

    yield ThreadItemDoneEvent(item=item.model_copy(update={"widget": last_state}))
```

---

## 3. OAuth/Auth Patterns

### 3.1 RFC 9728 Protected Resource Metadata

```python
# From authenticated_server_python/main.py
from mcp.shared.auth import ProtectedResourceMetadata

PROTECTED_RESOURCE_METADATA = ProtectedResourceMetadata(
    resource=RESOURCE_SERVER_URL,
    authorization_servers=[AUTHORIZATION_SERVER_URL],
    scopes_supported=RESOURCE_SCOPES,
)

# Expose well-known endpoint
@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
async def protected_resource_metadata(request):
    if request.method == "OPTIONS":
        return Response(status_code=204)
    return JSONResponse(PROTECTED_RESOURCE_METADATA.model_dump(mode="json"))
```

### 3.2 Mixed Auth Security Schemes

Tools can support both authenticated and unauthenticated access:

```python
# From authenticated_server_python/main.py
MIXED_TOOL_SECURITY_SCHEMES = [
    {"type": "noauth"},        # Anonymous access allowed
    {"type": "oauth2", "scopes": RESOURCE_SCOPES},
]

OAUTH_ONLY_SECURITY_SCHEMES = [
    {"type": "oauth2", "scopes": RESOURCE_SCOPES},
]

# Applied to tool _meta
meta = {
    "openai/outputTemplate": widget.template_uri,
    "openai/toolInvocation/invoking": widget.invoking,
    "openai/toolInvocation/invoked": widget.invoked,
    "openai/widgetAccessible": True,
}
if security_schemes is not None:
    meta["securitySchemes"] = deepcopy(security_schemes)
```

### 3.3 Bearer Token Extraction Pattern

```python
# From authenticated_server_python/main.py
def _get_bearer_token_from_request() -> str | None:
    try:
        request_context = mcp._mcp_server.request_context
    except LookupError:
        return None

    request = getattr(request_context, "request", None)
    if request is None:
        return None

    # Try headers object
    headers = getattr(request, "headers", None)
    if headers is not None:
        header_value = headers.get("authorization") or headers.get("Authorization")

    # Fallback: ASGI scope headers
    if header_value is None:
        scope = getattr(request, "scope", None)
        scope_headers = scope.get("headers") if isinstance(scope, dict) else None
        if scope_headers:
            for key, value in scope_headers:
                decoded_key = key.decode("latin-1").lower() if isinstance(key, bytes) else str(key).lower()
                if decoded_key == "authorization":
                    header_value = value.decode("latin-1") if isinstance(value, bytes) else str(value)
                    break

    if header_value and header_value.strip().lower().startswith("bearer "):
        return header_value[7:].strip() or None
    return None
```

### 3.4 OAuth Error Response Pattern

```python
# From authenticated_server_python/main.py
def _oauth_error_result(user_message, *, error="invalid_request", description=None):
    return types.ServerResult(
        types.CallToolResult(
            content=[types.TextContent(type="text", text=user_message)],
            _meta={
                "mcp/www_authenticate": [
                    _build_www_authenticate_value(error, description or user_message)
                ]
            },
            isError=True,
        )
    )

# Usage: conditional auth check
if tool_name == PAST_ORDERS_TOOL_NAME:
    if not _get_bearer_token_from_request():
        return _oauth_error_result(
            "Authentication required: no access token provided.",
            description="No access token was provided",
        )
```

### 3.5 Liveblocks Auth Proxy Pattern

```javascript
// From build-hours/22-chatgptapp-pingpong/server.js
if (req.method === "POST" && url.pathname === "/api/liveblocks-auth") {
    const cookies = parseCookies(req.headers.cookie);
    let userId = cookies[LIVEBLOCKS_COOKIE_NAME];
    if (!isValidUserId(userId)) {
        userId = randomUUID();
        res.setHeader("Set-Cookie", buildUserIdCookie(userId, isSecureRequest(req)));
    }
    const userInfo = { name: `Player ${userId.slice(0, 4)}` };
    const session = liveblocks.prepareSession(userId, { userInfo });
    session.allow(room, session.FULL_ACCESS);
    const { status, body: authBody } = await session.authorize();
    res.writeHead(status, { "content-type": "application/json" }).end(authBody);
}
```

---

## 4. Streaming & Transport Patterns

### 4.1 SSE Stream Class (openai-node)

The core `Stream<Item>` class wraps async iterators with abort control:

```typescript
// From openai-node/src/core/streaming.ts
export class Stream<Item> implements AsyncIterable<Item> {
  controller: AbortController;

  constructor(
    private iterator: () => AsyncIterator<Item>,
    controller: AbortController,
    client?: OpenAI,
  ) {
    this.controller = controller;
  }

  static fromSSEResponse<Item>(response: Response, controller: AbortController): Stream<Item> {
    let consumed = false;

    async function* iterator(): AsyncIterator<Item> {
      if (consumed) {
        throw new OpenAIError('Cannot iterate over a consumed stream, use `.tee()` to split.');
      }
      consumed = true;
      let done = false;
      try {
        for await (const sse of _iterSSEMessages(response, controller)) {
          if (done) continue;
          if (sse.data.startsWith('[DONE]')) { done = true; continue; }
          
          let data = JSON.parse(sse.data);
          if (data && data.error) {
            throw new APIError(undefined, data.error, undefined, response.headers);
          }
          yield data;
        }
        done = true;
      } catch (e) {
        if (isAbortError(e)) return;  // User-initiated abort = silent exit
        throw e;
      } finally {
        if (!done) controller.abort();  // User broke out = abort request
      }
    }

    return new Stream(iterator, controller);
  }
}
```

### 4.2 Stream Tee Pattern

```typescript
// From openai-node/src/core/streaming.ts
tee(): [Stream<Item>, Stream<Item>] {
  const left: Array<Promise<IteratorResult<Item>>> = [];
  const right: Array<Promise<IteratorResult<Item>>> = [];
  const iterator = this.iterator();

  const teeIterator = (queue: Array<Promise<IteratorResult<Item>>>): AsyncIterator<Item> => {
    return {
      next: () => {
        if (queue.length === 0) {
          const result = iterator.next();
          left.push(result);   // Both sides get the same promise
          right.push(result);
        }
        return queue.shift()!;
      },
    };
  };

  return [
    new Stream(() => teeIterator(left), this.controller),
    new Stream(() => teeIterator(right), this.controller),
  ];
}
```

### 4.3 SSE Chunk Parsing

```typescript
// From openai-node/src/core/streaming.ts
async function* iterSSEChunks(iterator: AsyncIterableIterator<Bytes>): AsyncGenerator<Uint8Array> {
  let data = new Uint8Array();

  for await (const chunk of iterator) {
    if (chunk == null) continue;
    const binaryChunk = chunk instanceof ArrayBuffer ? new Uint8Array(chunk)
      : typeof chunk === 'string' ? encodeUTF8(chunk) : chunk;

    let newData = new Uint8Array(data.length + binaryChunk.length);
    newData.set(data);
    newData.set(binaryChunk, data.length);
    data = newData;

    let patternIndex;
    while ((patternIndex = findDoubleNewlineIndex(data)) !== -1) {
      yield data.slice(0, patternIndex);
      data = data.slice(patternIndex);
    }
  }
  if (data.length > 0) yield data;
}

class SSEDecoder {
  private data: string[] = [];
  private event: string | null = null;
  private chunks: string[] = [];

  decode(line: string): ServerSentEvent | null {
    if (line.endsWith('\r')) line = line.substring(0, line.length - 1);
    if (!line) {
      if (!this.event && !this.data.length) return null;
      const sse = { event: this.event, data: this.data.join('\n'), raw: this.chunks };
      this.event = null; this.data = []; this.chunks = [];
      return sse;
    }
    this.chunks.push(line);
    if (line.startsWith(':')) return null;
    let [fieldname, _, value] = partition(line, ':');
    if (value.startsWith(' ')) value = value.substring(1);
    if (fieldname === 'event') this.event = value;
    else if (fieldname === 'data') this.data.push(value);
    return null;
  }
}
```

### 4.4 StreamableHTTP Transport (MCP)

```javascript
// From build-hours/22-chatgptapp-pingpong/server.js
if (url.pathname === "/mcp" && ["POST", "GET", "DELETE"].includes(req.method)) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");

    const server = createPingPongServer();
    const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,    // Stateless
        enableJsonResponse: true,
    });

    res.on("close", () => {
        transport.close();
        server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res);
}
```

### 4.5 ChatKit SSE Streaming Pattern

```python
# From chatkit-python/chatkit/server.py
async def _process_streaming(self, request, context):
    try:
        async for event in self._process_streaming_impl(request, context):
            b = self._serialize(event)
            yield b"data: " + b + b"\n\n"  # SSE format
    except asyncio.CancelledError:
        raise  # Let cancellation bubble up
    except Exception:
        logger.exception("Error while generating streamed response")
        raise
```

### 4.6 Transport Security Pattern

```python
# From openai-apps-sdk-examples
def _transport_security_settings() -> TransportSecuritySettings:
    allowed_hosts = _split_env_list(os.getenv("MCP_ALLOWED_HOSTS"))
    allowed_origins = _split_env_list(os.getenv("MCP_ALLOWED_ORIGINS"))
    if not allowed_hosts and not allowed_origins:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )
```

---

## 5. Agent Orchestration Patterns

### 5.1 Agent Definition (TypeScript)

```typescript
// From openai-agents-js/packages/agents-core/src/agent.ts
export class Agent<TContext = UnknownContext, TOutput extends AgentOutputType = TextOutput> {
  name: string;
  instructions: string | ((context: RunContext<TContext>, agent: Agent) => string | Promise<string>);
  handoffDescription?: string;
  handoffs: (Handoff | Agent)[];
  model: string | Model;
  modelSettings: ModelSettings;
  tools: Tool[];
  mcpServers: MCPServer[];
  inputGuardrails: InputGuardrail[];
  outputGuardrails: OutputGuardrail<TOutput>[];
  outputType?: AgentOutputSchema;
  toolUseBehavior: ToolUseBehavior;
  resetToolChoice: boolean;
}
```

### 5.2 Agent Definition (Python)

```python
# From openai-agents-python/src/agents/agent.py
@dataclass
class Agent(Generic[TContext]):
    name: str
    instructions: str | Callable | DynamicPromptFunction
    handoff_description: str | None = None
    handoffs: list[Handoff | Agent] = field(default_factory=list)
    model: str | Model | None = None
    model_settings: ModelSettings = field(default_factory=ModelSettings)
    tools: list[Tool] = field(default_factory=list)
    mcp_servers: list[MCPServer] = field(default_factory=list)
    input_guardrails: list[InputGuardrail] = field(default_factory=list)
    output_guardrails: list[OutputGuardrail] = field(default_factory=list)
    output_type: type[BaseModel] | None = None
    tool_use_behavior: ToolUseBehavior = "run_llm_again"
    hooks: AgentHooks | None = None
```

### 5.3 Run Loop Architecture

The runner executes agents in a turn-based loop:

```typescript
// From openai-agents-js/packages/agents-core/src/run.ts
export class Runner extends RunHooks<any, AgentOutputType<unknown>> {
  // Run loop:
  // 1. Invoke agent with input
  // 2. If final output (matches agent.outputType) → terminate
  // 3. If handoff → switch agent, loop again
  // 4. If tool calls → execute tools, loop again
  // 5. If maxTurns exceeded → throw MaxTurnsExceeded

  async run(agent, input, options): Promise<RunResult | StreamedRunResult> {
    // ... orchestration logic
  }
}
```

### 5.4 Run Configuration

```typescript
// From openai-agents-js/packages/agents-core/src/run.ts
export type RunConfig = {
  model?: string | Model;
  modelProvider: ModelProvider;
  modelSettings?: ModelSettings;
  handoffInputFilter?: HandoffInputFilter;
  inputGuardrails?: InputGuardrail[];
  outputGuardrails?: OutputGuardrail[];
  tracingDisabled: boolean;
  traceIncludeSensitiveData: boolean;
  workflowName?: string;
  traceId?: string;
  groupId?: string;                      // Link traces from same conversation
  traceMetadata?: Record<string, string>;
  tracing?: TracingConfig;
  sessionInputCallback?: SessionInputCallback;
  callModelInputFilter?: CallModelInputFilter;
  toolErrorFormatter?: ToolErrorFormatter;
};

type SharedRunOptions = {
  context?: TContext | RunContext<TContext>;
  maxTurns?: number;
  signal?: AbortSignal;
  previousResponseId?: string;
  conversationId?: string;
  session?: Session;
  sessionInputCallback?: SessionInputCallback;
  callModelInputFilter?: CallModelInputFilter;
  toolErrorFormatter?: ToolErrorFormatter;
  tracing?: TracingConfig;
  errorHandlers?: RunErrorHandlers;
};
```

### 5.5 Function Overload Pattern for Stream/Non-Stream

```typescript
// From openai-agents-js/packages/agents-core/src/run.ts
export async function run<TAgent extends Agent<any, any>, TContext = undefined>(
  agent: TAgent,
  input: string | AgentInputItem[] | RunState<TContext, TAgent>,
  options?: NonStreamRunOptions<TContext, TAgent>,
): Promise<RunResult<TContext, TAgent>>;

export async function run<TAgent extends Agent<any, any>, TContext = undefined>(
  agent: TAgent,
  input: string | AgentInputItem[] | RunState<TContext, TAgent>,
  options?: StreamRunOptions<TContext, TAgent>,
): Promise<StreamedRunResult<TContext, TAgent>>;

export async function run(agent, input, options?) {
  const runner = getDefaultRunner();
  return await runner.run(agent, input, options);
}
```

### 5.6 Dual Agent Parallel Execution

```typescript
// From build-hours/21-agentic-memory/app/api/agents/chat/route.ts
const [agentAResult, agentBResult] = await Promise.all([
  runPythonAgent({ agentId: "agentA", message, history: historyA, config: agentAConfig }),
  runPythonAgent({ agentId: "agentB", message, history: historyB, config: agentBConfig }),
]);

return NextResponse.json({
  agentA: {
    response: agentAResult.response,
    toolResults: agentAResult.toolResults,
    tokenUsage: agentAResult.tokenUsage,
    summary: agentAResult.summary,
    contextTrimmed: agentAResult.contextTrimmed,
    contextSummarized: agentAResult.contextSummarized,
    contextCompacted: agentAResult.contextCompacted,
  },
  agentB: { /* same structure */ },
});
```

---

## 6. Guardrail Patterns

### 6.1 Input Guardrail (TypeScript)

```typescript
// From openai-agents-js/packages/agents-core/src/guardrail.ts
export interface GuardrailFunctionOutput {
  tripwireTriggered: boolean;  // If true, agent execution halts
  outputInfo: any;             // Granular check results
}

export interface InputGuardrail {
  name: string;
  execute: InputGuardrailFunction;
  runInParallel?: boolean;  // true = run alongside agent, false = block first
}

export interface InputGuardrailResult {
  guardrail: InputGuardrailMetadata;
  output: GuardrailFunctionOutput;
}
```

### 6.2 Input Guardrail (Python)

```python
# From openai-agents-python/src/agents/guardrail.py
@dataclass
class InputGuardrail(Generic[TContext]):
    """Checks that run in parallel with or before the agent.
    If tripwire_triggered is True, raises InputGuardrailTripwireTriggered."""
    
    guardrail_function: Callable[
        [RunContextWrapper[TContext], Agent[Any], str | list[TResponseInputItem]],
        MaybeAwaitable[GuardrailFunctionOutput],
    ]
    name: str | None = None
    run_in_parallel: bool = True  # Default: parallel execution
```

### 6.3 Output Guardrail Pattern

```python
@dataclass
class OutputGuardrailResult:
    guardrail: OutputGuardrail[Any]
    agent_output: Any       # The output that was checked
    agent: Agent[Any]       # The agent that produced it
    output: GuardrailFunctionOutput
```

---

## 7. Handoff Patterns

### 7.1 Handoff Class (TypeScript)

```typescript
// From openai-agents-js/packages/agents-core/src/handoff.ts
export class Handoff<TContext = UnknownContext, TOutput extends AgentOutputType = TextOutput> {
  toolName: string;           // e.g., "transfer_to_billing_agent"
  toolDescription: string;
  inputJsonSchema: JsonObjectSchema<any>;
  strictJsonSchema: boolean = true;
  
  onInvokeHandoff: (context: RunContext<TContext>, args: string) => 
    Promise<Agent<TContext, TOutput>> | Agent<TContext, TOutput>;
  
  agentName: string;
  inputFilter?: HandoffInputFilter;
  agent: Agent<TContext, TOutput>;
  isEnabled: HandoffEnabledFunction<TContext> = async () => true;

  getHandoffAsFunctionTool() {
    return {
      type: 'function',
      name: this.toolName,
      description: this.toolDescription,
      parameters: this.inputJsonSchema,
      strict: this.strictJsonSchema,
    };
  }
}
```

### 7.2 Handoff Tool Naming Convention

```typescript
function defaultHandoffToolName(agent) {
  return `transfer_to_${toFunctionToolName(agent.name)}`;
}

function defaultHandoffToolDescription(agent) {
  return `Handoff to the ${agent.name} agent to handle the request. ${agent.handoffDescription ?? ''}`;
}

// Transfer message format
function getTransferMessage(agent) {
  return JSON.stringify({ assistant: agent.name });
}
```

### 7.3 Handoff Input Filter

```typescript
export type HandoffInputData = {
  inputHistory: string | AgentInputItem[];  // Pre-run history
  preHandoffItems: RunItem[];               // Items before handoff turn
  newItems: RunItem[];                      // Items from current turn (includes handoff trigger)
  runContext?: RunContext<any>;
};

export type HandoffInputFilter = (input: HandoffInputData) => HandoffInputData;
```

### 7.4 Conditional Handoff Enablement

```typescript
type HandoffEnabledPredicate<TContext> = (args: {
  runContext: RunContext<TContext>;
  agent: Agent<any, any>;
}) => boolean | Promise<boolean>;

export type HandoffConfig<TInputType, TContext> = {
  toolNameOverride?: string;
  toolDescriptionOverride?: string;
  onHandoff?: OnHandoffCallback<TInputType>;
  inputType?: TInputType;           // Zod schema for validation
  inputFilter?: HandoffInputFilter;
  isEnabled?: boolean | HandoffEnabledPredicate<TContext>;
};
```

---

## 8. Memory & Session Patterns

### 8.1 Session Interface (TypeScript)

```typescript
// From openai-agents-js/packages/agents-core/src/memory/session.ts
export type SessionInputCallback = (
  historyItems: AgentInputItem[],
  newItems: AgentInputItem[],
) => AgentInputItem[] | Promise<AgentInputItem[]>;

export interface Session {
  getSessionId(): Promise<string>;
  getItems(limit?: number): Promise<AgentInputItem[]>;
  addItems(items: AgentInputItem[]): Promise<void>;
  popItem(): Promise<AgentInputItem | undefined>;
  clearSession(): Promise<void>;
}
```

### 8.2 Compaction-Aware Session

```typescript
// From openai-agents-js/packages/agents-core/src/memory/session.ts
export type OpenAIResponsesCompactionArgs = {
  responseId?: string;
  compactionMode?: 'previous_response_id' | 'input' | 'auto';
  store?: boolean;
  force?: boolean;
};

export interface OpenAIResponsesCompactionAwareSession extends Session {
  runCompaction(args?: OpenAIResponsesCompactionArgs):
    | Promise<OpenAIResponsesCompactionResult | null>
    | OpenAIResponsesCompactionResult
    | null;
}

// Type guard
export function isOpenAIResponsesCompactionAwareSession(
  session: Session | undefined,
): session is OpenAIResponsesCompactionAwareSession {
  return !!session && typeof (session as any).runCompaction === 'function';
}
```

### 8.3 Memory Management Strategies (Agentic Memory Example)

**Trimming:** Keep only the last N turns.
```typescript
// From build-hours/21-agentic-memory
type ConfigureTrimmingPayload = {
  enable?: boolean;
  maxTurns?: number;
  keepLast?: number;
  agentIds?: string[];
};
```

**Compacting:** Condense history after N turns using the API.
```typescript
type ConfigureCompactingPayload = {
  enable?: boolean;
  trigger?: { turns?: number };
  keep?: number;
  excludeTools?: string[];
  clearToolInputs?: boolean;
  agentIds?: string[];
};
```

**Summarization:** Replace old history with a summary.

### 8.4 Session Persistence Runner Hooks

```typescript
// From openai-agents-js/packages/agents-core/src/run.ts (imports)
import {
  createSessionPersistenceTracker,
  prepareInputItemsWithSession,
  saveStreamInputToSession,
  saveStreamResultToSession,
  saveToSession,
} from './runner/sessionPersistence';
```

---

## 9. Error Handling Patterns

### 9.1 Hierarchical Error Classes (openai-node)

```typescript
// From openai-node/src/core/error.ts
export class OpenAIError extends Error {}

export class APIError<TStatus, THeaders, TError> extends OpenAIError {
  readonly status: TStatus;
  readonly headers: THeaders;
  readonly error: TError;
  readonly code: string | null | undefined;
  readonly param: string | null | undefined;
  readonly type: string | undefined;
  readonly requestID: string | null | undefined;

  static generate(status, errorResponse, message, headers): APIError {
    if (!status || !headers) return new APIConnectionError({ message, cause: castToError(errorResponse) });
    
    const error = errorResponse?.['error'];
    if (status === 400) return new BadRequestError(status, error, message, headers);
    if (status === 401) return new AuthenticationError(status, error, message, headers);
    if (status === 403) return new PermissionDeniedError(status, error, message, headers);
    if (status === 404) return new NotFoundError(status, error, message, headers);
    if (status === 409) return new ConflictError(status, error, message, headers);
    if (status === 422) return new UnprocessableEntityError(status, error, message, headers);
    if (status === 429) return new RateLimitError(status, error, message, headers);
    if (status >= 500) return new InternalServerError(status, error, message, headers);
    return new APIError(status, error, message, headers);
  }
}

// Specific error types with typed status codes
export class BadRequestError extends APIError<400, Headers> {}
export class AuthenticationError extends APIError<401, Headers> {}
export class RateLimitError extends APIError<429, Headers> {}
export class InternalServerError extends APIError<number, Headers> {}
export class APIUserAbortError extends APIError<undefined, undefined, undefined> {}
export class APIConnectionError extends APIError<undefined, undefined, undefined> {
  constructor({ message, cause }) {
    super(undefined, undefined, message || 'Connection error.', undefined);
    if (cause) this.cause = cause;
  }
}
export class APIConnectionTimeoutError extends APIConnectionError {
  constructor({ message } = {}) {
    super({ message: message ?? 'Request timed out.' });
  }
}

// Content-specific errors
export class LengthFinishReasonError extends OpenAIError {}
export class ContentFilterFinishReasonError extends OpenAIError {}
export class InvalidWebhookSignatureError extends Error {}
```

### 9.2 MCP Tool Error Handling (Non-Fatal)

```python
# From openai-agents-python/src/agents/mcp/util.py
async def invoke_func(ctx, input_json):
    try:
        return await invoke_func_impl(ctx, input_json)
    except Exception as e:
        if effective_failure_error_function is None:
            raise  # Re-raise if no error handler

        # Convert exception to error message for the model
        result = effective_failure_error_function(ctx, e)
        if inspect.isawaitable(result):
            result = await result

        # Attach to tracing span (non-fatal)
        _error_tracing.attach_error_to_current_span(
            SpanError(message="Error running tool (non-fatal)", data={"tool_name": tool.name, "error": str(e)})
        )
        return result  # Model sees error as tool output, continues
```

### 9.3 Agent Exception Hierarchy

```python
# From openai-agents-python/src/agents/exceptions.py (inferred from imports)
class AgentsException(Exception): pass
class UserError(AgentsException): pass
class ModelBehaviorError(AgentsException): pass
class MaxTurnsExceeded(AgentsException): pass
class InputGuardrailTripwireTriggered(AgentsException): pass
```

### 9.4 Run Error Handlers

```typescript
// From openai-agents-js/packages/agents-core/src/run.ts
export type ToolErrorFormatterArgs<TContext = unknown> = {
  kind: 'approval_rejected';
  toolType: 'function' | 'computer' | 'shell' | 'apply_patch';
  toolName: string;
  callId: string;
  defaultMessage: string;
  runContext: RunContext<TContext>;
};

export type ToolErrorFormatter<TContext = unknown> = (
  args: ToolErrorFormatterArgs<TContext>,
) => Promise<string | undefined> | string | undefined;
```

### 9.5 MCP Tool Error Function (TypeScript)

```typescript
// From openai-agents-js/packages/agents-core/src/mcp.ts
type MCPToolErrorFunction = (args: {
  context: RunContext;
  error: Error | unknown;
}) => Promise<string> | string;

export interface MCPServer {
  errorFunction?: MCPToolErrorFunction | null;  // null = rethrow instead
  // ...
}
```

### 9.6 Pydantic Validation Error Handling

```python
# From shopping_cart_python/main.py
try:
    payload = AddToCartInput.model_validate(req.params.arguments or {})
except ValidationError as exc:
    return types.ServerResult(
        types.CallToolResult(
            content=[types.TextContent(type="text", text=f"Invalid input: {exc.errors()}")],
            isError=True,
        )
    )
```

---

## 10. Architecture & Dependency Patterns

### 10.1 MCP Server Interface (TypeScript)

```typescript
// From openai-agents-js/packages/agents-core/src/mcp.ts
export interface MCPServer {
  cacheToolsList: boolean;
  toolFilter?: MCPToolFilterCallable | MCPToolFilterStatic;
  toolMetaResolver?: MCPToolMetaResolver;
  errorFunction?: MCPToolErrorFunction | null;
  connect(): Promise<void>;
  readonly name: string;
  close(): Promise<void>;
  listTools(): Promise<MCPTool[]>;
  callTool(toolName: string, args: Record<string, unknown> | null,
           meta?: Record<string, unknown> | null): Promise<CallToolResultContent>;
  invalidateToolsCache(): Promise<void>;
}

// Three transport base classes
export abstract class BaseMCPServerStdio implements MCPServer { /* ... */ }
export abstract class BaseMCPServerStreamableHttp implements MCPServer { /* ... */ }
export abstract class BaseMCPServerSSE implements MCPServer { /* ... */ }
```

### 10.2 ChatKit Server Architecture

```python
# From chatkit-python/chatkit/server.py
class ChatKitServer(ABC, Generic[TContext]):
    def __init__(self, store: Store[TContext], attachment_store: AttachmentStore[TContext] | None = None):
        self.store = store
        self.attachment_store = attachment_store

    @abstractmethod
    def respond(self, thread, input_user_message, context) -> AsyncIterator[ThreadStreamEvent]:
        pass

    async def add_feedback(self, thread_id, item_ids, feedback, context) -> None:
        pass

    async def transcribe(self, audio_input, context) -> TranscriptionResult:
        raise NotImplementedError

    def action(self, thread, action, sender, context) -> AsyncIterator[ThreadStreamEvent]:
        raise NotImplementedError

    def get_stream_options(self, thread, context) -> StreamOptions:
        return StreamOptions(allow_cancel=True)

    async def handle_stream_cancelled(self, thread, pending_items, context):
        """Persist non-empty pending messages, add cancellation context item."""
        pass
```

### 10.3 Request Routing Pattern (ChatKit)

```python
# From chatkit-python/chatkit/server.py
async def process(self, request, context) -> StreamingResult | NonStreamingResult:
    parsed_request = TypeAdapter[ChatKitReq](ChatKitReq).validate_json(request)
    
    if is_streaming_req(parsed_request):
        return StreamingResult(self._process_streaming(parsed_request, context))
    else:
        return NonStreamingResult(await self._process_non_streaming(parsed_request, context))

async def _process_non_streaming(self, request, context) -> bytes:
    match request:
        case ThreadsGetByIdReq(): ...
        case ThreadsListReq(): ...
        case ItemsFeedbackReq(): ...
        case AttachmentsCreateReq(): ...
        case AttachmentsDeleteReq(): ...
        case InputTranscribeReq(): ...
        case ItemsListReq(): ...
        case ThreadsUpdateReq(): ...
        case ThreadsDeleteReq(): ...
        case _: assert_never(request)

async def _process_streaming_impl(self, request, context):
    match request:
        case ThreadsCreateReq(): ...
        case ThreadsAddUserMessageReq(): ...
        case ThreadsAddClientToolOutputReq(): ...
        case ThreadsRetryAfterItemReq(): ...
        case ThreadsCustomActionReq(): ...
        case _: assert_never(request)
```

### 10.4 Runner Module Organization

```typescript
// From openai-agents-js/packages/agents-core/src/run.ts (imports show architecture)
import { processModelResponse } from './runner/modelOutputs';
import { addStepToRunResult, streamStepItemsToRunResult } from './runner/streaming';
import { createSessionPersistenceTracker } from './runner/sessionPersistence';
import { resolveTurnAfterModelResponse } from './runner/turnResolution';
import { prepareTurn } from './runner/turnPreparation';
import { applyTurnResult, handleInterruptedOutcome, resumeInterruptedTurn } from './runner/runLoop';
import { applyTraceOverrides, getTracing } from './runner/tracing';
import { tryHandleRunError } from './runner/errorHandlers';
import { createGuardrailTracker, runOutputGuardrails } from './runner/guardrails';
import { selectModel, adjustModelSettingsForNonGPT5RunnerModel } from './runner/modelSettings';
```

### 10.5 Lazy Debug Logging

```typescript
// From openai-agents-js/packages/agents-core/src/mcp.ts
protected debugLog(buildMessage: () => string): void {
    if (debug.enabled(this.logger.namespace)) {
        this.logger.debug(buildMessage());  // Only build string if logging enabled
    }
}
```

---

## 11. TypeScript/Python Type Patterns

### 11.1 Generic Agent Type Parameters

```typescript
// TContext = shared state across agent run
// TOutput = output type (TextOutput | structured)
export class Agent<TContext = UnknownContext, TOutput extends AgentOutputType = TextOutput> {
  // ...
}

export type UnknownContext = unknown;
export type TextOutput = string;
```

### 11.2 Conditional Type for Event Handlers (ChatKit React)

```typescript
// From chatkit-js/packages/chatkit-react/src/useChatKit.ts
type DotToCamelCase<S extends string> = S extends `${infer Head}.${infer Tail}`
  ? `${Head}${Capitalize<DotToCamelCase<Tail>>}`
  : S;

type ToEventHandlerKey<K extends keyof ChatKitEvents> =
  DotToCamelCase<K> extends `chatkit${infer EventName}`
    ? `on${Capitalize<EventName>}`
    : never;

type ChatKitEventHandlers = Partial<{
  [K in keyof ChatKitEvents as ToEventHandlerKey<K>]: ChatKitEvents[K] extends CustomEvent<infer Detail>
    ? Detail extends undefined ? () => void : (event: Detail) => void
    : never;
}>;
```

### 11.3 Config Merge Override Pattern

```typescript
// From apps-sdk-ui
interface DefaultConfig {
  LinkComponent: "a";
}

declare global {
  interface AppsSDKUIConfig {}  // User extends this
}

type MergeOverrides<Defaults, Overrides> = Omit<Defaults, keyof Overrides> & Overrides;
export type Config = MergeOverrides<DefaultConfig, AppsSDKUIConfig>;
```

### 11.4 MaybeAwaitable Pattern (Python)

```python
# Used throughout openai-agents-python
MaybeAwaitable = Union[T, Awaitable[T]]

# Example usage
guardrail_function: Callable[
    [RunContextWrapper[TContext], Agent[Any], str | list[TResponseInputItem]],
    MaybeAwaitable[GuardrailFunctionOutput],
]

# Runtime check
result = guardrail_function(ctx, agent, input)
if inspect.isawaitable(result):
    result = await result
```

### 11.5 TypedDict for Static Configuration

```python
# From openai-agents-python/src/agents/mcp/util.py
class ToolFilterStatic(TypedDict):
    allowed_tool_names: NotRequired[list[str]]
    blocked_tool_names: NotRequired[list[str]]
```

### 11.6 APIError Generic Type Parameters

```typescript
// From openai-node/src/core/error.ts
export class APIError<
  TStatus extends number | undefined = number | undefined,
  THeaders extends Headers | undefined = Headers | undefined,
  TError extends Object | undefined = Object | undefined,
> extends OpenAIError {
  readonly status: TStatus;
  readonly headers: THeaders;
  readonly error: TError;
}

// Specific errors fix the status code type
export class BadRequestError extends APIError<400, Headers> {}
export class RateLimitError extends APIError<429, Headers> {}
```

### 11.7 Pydantic Schema Generation for Tool Input

```python
# From shopping_cart_python/main.py
class CartItem(BaseModel):
    name: str = Field(..., description="Name of the item")
    quantity: int = Field(default=1, ge=1, description="How many units")
    model_config = ConfigDict(populate_by_name=True, extra="allow")

class AddToCartInput(BaseModel):
    items: List[CartItem] = Field(..., description="List of items to add")
    cart_id: str | None = Field(default=None, alias="cartId")
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

# Auto-generate JSON Schema from Pydantic model
TOOL_INPUT_SCHEMA = AddToCartInput.model_json_schema(by_alias=True)
```

---

## 12. UI/Component Patterns

### 12.1 Provider Pattern (Apps SDK UI)

```typescript
// From apps-sdk-ui/src/components/AppsSDKUIProvider
export const AppsSDKUIContext = createContext<AppsSDKUIContextValue | null>(null);

export function AppsSDKUIProvider({ children, linkComponent }) {
  return (
    <AppsSDKUIContext.Provider value={{ linkComponent }}>
      {children}
    </AppsSDKUIContext.Provider>
  );
}
```

### 12.2 ChatKit React Hook Pattern

```typescript
// From chatkit-js/packages/chatkit-react/src/useChatKit.ts
const CHATKIT_METHOD_NAMES = Object.freeze([
  'focusComposer', 'setThreadId', 'sendUserMessage',
  'setComposerValue', 'fetchUpdates', 'sendCustomAction',
  'showHistory', 'hideHistory',
] as const);

export function useChatKit(options: UseChatKitOptions): UseChatKitReturn {
  const ref = React.useRef<OpenAIChatKit | null>(null);
  const stableOptions = useStableOptions(options);

  const methods = React.useMemo(() => {
    return CHATKIT_METHOD_NAMES.reduce((acc, key) => {
      acc[key] = (...args) => {
        if (!ref.current) {
          console.warn('ChatKit element is not mounted');
          return;
        }
        return ref.current[key](...args);
      };
      return acc;
    }, {} as ChatKitMethods);
  }, []);

  // Separate options from event handlers
  const control = React.useMemo(() => {
    const options = {};
    const handlers = {};
    for (const [key, value] of Object.entries(stableOptions)) {
      if (/^on[A-Z]/.test(key) && key !== 'onClientTool') {
        handlers[key] = value;
      } else {
        options[key] = value;
      }
    }
    return { setInstance, options, handlers };
  }, [stableOptions, setInstance]);

  return React.useMemo(() => ({ ...methods, control, ref }), [methods, control]);
}
```

---

## 13. ChatKit Server Patterns

### 13.1 Store Abstraction

```python
# From chatkit-python/chatkit/store.py (inferred from imports)
class Store(ABC, Generic[TContext]):
    def generate_thread_id(self, context: TContext) -> str: ...
    def generate_item_id(self, item_type: StoreItemType, thread, context) -> str: ...
    async def save_thread(self, thread: ThreadMetadata, context: TContext): ...
    async def load_thread(self, thread_id: str, context: TContext) -> ThreadMetadata: ...
    async def load_threads(self, limit, after, order, context) -> Page: ...
    async def delete_thread(self, thread_id: str, context: TContext): ...
    async def load_thread_items(self, thread_id, limit, order, after, context) -> Page: ...
    async def add_thread_item(self, thread_id, item, context): ...
    async def save_item(self, thread_id, item, context): ...
    async def save_attachment(self, attachment, context): ...
    async def delete_attachment(self, attachment_id, context): ...
```

### 13.2 Thread Stream Events

```python
# Event hierarchy from chatkit-python
ThreadStreamEvent = Union[
    ThreadCreatedEvent,
    ThreadUpdatedEvent,
    ThreadItemAddedEvent,
    ThreadItemUpdatedEvent,
    ThreadItemDoneEvent,
    ThreadItemRemovedEvent,
    ThreadItemReplacedEvent,
    StreamOptionsEvent,
    ErrorEvent,
    WidgetStreamingTextValueDelta,
    WidgetRootUpdated,
    WidgetComponentUpdated,
    WorkflowTaskAdded,
    WorkflowTaskUpdated,
]
```

### 13.3 Stream Cancellation Handling

```python
# From chatkit-python/chatkit/server.py
async def handle_stream_cancelled(self, thread, pending_items, context):
    # Save non-empty pending messages
    for item in pending_items:
        if isinstance(item, AssistantMessageItem):
            is_empty = len(item.content) == 0 or all(not c.text.strip() for c in item.content)
            if not is_empty:
                await self.store.add_thread_item(thread.id, item, context=context)

    # Add hidden context so subsequent responses don't try to continue
    await self.store.add_thread_item(
        thread.id,
        SDKHiddenContextItem(
            thread_id=thread.id,
            created_at=datetime.now(),
            id=self.store.generate_item_id("sdk_hidden_context", thread, context),
            content="The user cancelled the stream. Stop responding to the prior request.",
        ),
        context=context,
    )
```

### 13.4 User Agent Override for Tracing

```python
# From chatkit-python/chatkit/server.py
@contextmanager
def agents_sdk_user_agent_override():
    ua = f"Agents/Python {agents.__version__} ChatKit/Python {__version__}"
    chat_completions_token = chat_completions_headers_override.set({"User-Agent": ua})
    responses_token = responses_headers_override.set({"User-Agent": ua})
    yield
    chat_completions_headers_override.reset(chat_completions_token)
    responses_headers_override.reset(responses_token)
```

---

## 14. Tool Filtering Patterns

### 14.1 Static Tool Filter

```python
# From openai-agents-python/src/agents/mcp/util.py
class ToolFilterStatic(TypedDict):
    allowed_tool_names: NotRequired[list[str]]  # Whitelist
    blocked_tool_names: NotRequired[list[str]]  # Blacklist

def create_static_tool_filter(
    allowed_tool_names: list[str] | None = None,
    blocked_tool_names: list[str] | None = None,
) -> ToolFilterStatic | None:
    if allowed_tool_names is None and blocked_tool_names is None:
        return None
    filter_dict: ToolFilterStatic = {}
    if allowed_tool_names is not None:
        filter_dict["allowed_tool_names"] = allowed_tool_names
    if blocked_tool_names is not None:
        filter_dict["blocked_tool_names"] = blocked_tool_names
    return filter_dict
```

### 14.2 Dynamic Tool Filter

```python
# From openai-agents-python/src/agents/mcp/util.py
@dataclass
class ToolFilterContext:
    run_context: RunContextWrapper[Any]
    agent: AgentBase
    server_name: str

ToolFilterCallable = Callable[[ToolFilterContext, MCPTool], MaybeAwaitable[bool]]

# Union type for flexibility
ToolFilter = ToolFilterCallable | ToolFilterStatic | None
```

### 14.3 Duplicate Tool Name Detection

```python
# From openai-agents-python/src/agents/mcp/util.py
@classmethod
async def get_all_function_tools(cls, servers, ...):
    tools = []
    tool_names: set[str] = set()
    for server in servers:
        server_tools = await cls.get_function_tools(server, ...)
        server_tool_names = {tool.name for tool in server_tools}
        if len(server_tool_names & tool_names) > 0:
            raise UserError(
                f"Duplicate tool names found across MCP servers: {server_tool_names & tool_names}"
            )
        tool_names.update(server_tool_names)
        tools.extend(server_tools)
    return tools
```

---

## Summary: Key Patterns for MCP Server Rebuild

1. **Widget `_meta` fields** are the core protocol for ChatGPT app connectors — `outputTemplate`, `toolInvocation/invoking|invoked`, `widgetAccessible`, `widgetSessionId`, `visibility`, `widgetCSP`
2. **`text/html+skybridge`** is the MIME type for widget HTML resources
3. **`ui://widget/`** is the URI scheme for widget templates
4. **`structuredContent`** provides JSON data to widgets alongside `content` text for the model
5. **`securitySchemes`** with `noauth`/`oauth2` types enable mixed auth per-tool
6. **Bearer token extraction** from MCP request context enables auth-gated tools
7. **`mcp/www_authenticate`** in `_meta` triggers OAuth flow on auth failure
8. **RFC 9728** `.well-known/oauth-protected-resource` endpoint for resource server discovery
9. **Tool annotations** (`destructiveHint`, `readOnlyHint`, `openWorldHint`) control approval prompts
10. **Private tools** (`openai/visibility: "private"`) are widget-only, hidden from the model
11. **Session compaction** supports `previous_response_id`, `input`, and `auto` modes
12. **Guardrails** can run in parallel or block, with tripwire triggering for immediate halt
13. **Handoffs** use `transfer_to_{agent_name}` naming convention with optional input filters
14. **Error handling** is non-fatal by default — tool errors become model-visible messages
15. **Stream tee** pattern allows splitting a single stream for parallel consumption
16. **Widget diffing** sends incremental text deltas instead of full replacements
17. **Transport security** settings control DNS rebinding protection per-server
