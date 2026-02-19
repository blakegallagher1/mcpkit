import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

export interface WidgetCSP {
  connect_domains?: string[];
  resource_domains?: string[];
}

export interface WidgetDescriptor {
  id: string;
  title: string;
  description: string;
  html: string;
  templateUri: string;
  invoking?: string;
  invoked?: string;
  csp?: WidgetCSP;
  prefersBorder?: boolean;
  sessionEnabled?: boolean;
  widgetDomain?: string;
}

export function createWidgetMeta(widget: WidgetDescriptor, sessionId?: string) {
  const meta: Record<string, unknown> = {
    'openai/outputTemplate': widget.templateUri,
    'openai/widgetAccessible': true
  };

  if (widget.invoking) {
    meta['openai/toolInvocation/invoking'] = widget.invoking;
  }
  if (widget.invoked) {
    meta['openai/toolInvocation/invoked'] = widget.invoked;
  }
  if (widget.csp) {
    meta['openai/widgetCSP'] = widget.csp;
  }
  if (widget.prefersBorder !== undefined) {
    meta['openai/widgetPrefersBorder'] = widget.prefersBorder;
  }
  if (sessionId) {
    meta['openai/widgetSessionId'] = sessionId;
  }

  return meta;
}

export function createPrivateToolMeta(widget: WidgetDescriptor) {
  return {
    ...createWidgetMeta(widget),
    'openai/visibility': 'private'
  };
}

export function registerWidgetResource(
  server: McpServer,
  widget: WidgetDescriptor
) {
  const resourceMeta: Record<string, unknown> = {};
  if (widget.widgetDomain) {
    resourceMeta['openai/widgetDomain'] = widget.widgetDomain;
  }
  if (widget.prefersBorder !== undefined) {
    resourceMeta['openai/widgetPrefersBorder'] = widget.prefersBorder;
  }
  if (widget.csp) {
    resourceMeta['openai/widgetCSP'] = widget.csp;
  }

  server.resource(
    widget.id,
    widget.templateUri,
    { mimeType: 'text/html+skybridge' },
    async () => ({
      contents: [{
        uri: widget.templateUri,
        mimeType: 'text/html+skybridge' as string,
        text: widget.html,
        _meta: resourceMeta
      }]
    })
  );
}

export function widgetToolResult(
  textForModel: string,
  structuredContent: Record<string, unknown>,
  widget: WidgetDescriptor,
  sessionId?: string
) {
  const meta = createWidgetMeta(widget, sessionId);
  return {
    content: [{ type: 'text' as const, text: textForModel }],
    structuredContent,
    _meta: meta
  };
}

export const SKYBRIDGE_MIME = 'text/html+skybridge' as const;
export const WIDGET_URI_SCHEME = 'ui://widget/' as const;

export function widgetUri(filename: string): string {
  return `${WIDGET_URI_SCHEME}${filename}`;
}
