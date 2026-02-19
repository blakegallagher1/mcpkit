export interface TransportSecuritySettings {
  enableDnsRebindingProtection: boolean;
  allowedHosts?: string[];
  allowedOrigins?: string[];
}

export function createTransportSecuritySettings(): TransportSecuritySettings {
  const allowedHosts = splitEnvList(process.env.MCP_ALLOWED_HOSTS);
  const allowedOrigins = splitEnvList(process.env.MCP_ALLOWED_ORIGINS);

  if (!allowedHosts.length && !allowedOrigins.length) {
    return { enableDnsRebindingProtection: false };
  }

  return {
    enableDnsRebindingProtection: true,
    allowedHosts,
    allowedOrigins
  };
}

function splitEnvList(value: string | undefined): string[] {
  if (!value) return [];
  return value.split(',').map(s => s.trim()).filter(s => s.length > 0);
}

export function transportSecurityMiddleware(settings: TransportSecuritySettings) {
  return (req: { headers: Record<string, string | string[] | undefined>; hostname?: string }, res: { status: (code: number) => { json: (body: unknown) => void } }, next: () => void) => {
    if (!settings.enableDnsRebindingProtection) {
      return next();
    }

    const host = (Array.isArray(req.headers.host) ? req.headers.host[0] : req.headers.host) ?? '';
    const origin = (Array.isArray(req.headers.origin) ? req.headers.origin[0] : req.headers.origin) ?? '';

    if (settings.allowedHosts?.length) {
      const hostname = host.split(':')[0];
      if (!settings.allowedHosts.includes(hostname)) {
        res.status(403).json({ error: 'forbidden', detail: 'Host not allowed' });
        return;
      }
    }

    if (settings.allowedOrigins?.length && origin) {
      if (!settings.allowedOrigins.includes(origin)) {
        res.status(403).json({ error: 'forbidden', detail: 'Origin not allowed' });
        return;
      }
    }

    next();
  };
}
