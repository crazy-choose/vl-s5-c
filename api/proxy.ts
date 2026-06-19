// Node.js runtime — process.env 原生可用，declare 仅消除 TS 编译警告
declare const process: {
  env: {
    PROXY_USER?: string;
    PROXY_PASS?: string;
    [key: string]: string | undefined;
  };
};

export const config = {
  runtime: 'nodejs',
  maxDuration: 60, // Hobby 上限 60s (Pro 可设 300)
};

// Node.js runtime: 50s TTFT 留 10s buffer 给响应构造 + body 透传启动。
// body 读阶段不限时（Vercel Node.js Hobby 60s / Pro 300s wall 自然管控）。
const FETCH_TTFT_TIMEOUT_MS = 50_000;

const PROXY_AUTH = new Map<string, string>();
let authInitialized = false;

function ensureAuth(): void {
  if (authInitialized) return;
  const u = process.env.PROXY_USER;
  if (u) PROXY_AUTH.set(u, process.env.PROXY_PASS || '');
  authInitialized = true;
}

function checkAuth(request: Request): boolean {
  const proxyUser = process.env.PROXY_USER;
  if (!proxyUser) return true;

  const auth = request.headers.get('proxy-authorization') || request.headers.get('x-proxy-authorization');
  if (!auth?.startsWith('Basic ')) return false;

  try {
    const [user, pass] = atob(auth.slice(6)).split(':');
    return PROXY_AUTH.get(user) === pass;
  } catch {
    return false;
  }
}

function challengeAuth(): Response {
  return new Response('Proxy Authentication Required', {
    status: 407,
    headers: { 'Proxy-Authenticate': 'Basic realm="Proxy"' },
  });
}

function buildTargetUrl(requestUrl: string): { url: string; ok: boolean } {
  const url = new URL(requestUrl);
  const pathVal = url.searchParams.get('path');
  if (!pathVal) {
    return { url: '', ok: false };
  }

  const upstreamParams = new URLSearchParams(url.search);
  upstreamParams.delete('path');
  const searchStr = upstreamParams.toString();
  const searchPart = searchStr ? `?${searchStr}` : '';

  const slashIndex = pathVal.indexOf('/');
  if (slashIndex === -1) {
    return { url: '', ok: false };
  }

  const targetHost = pathVal.slice(0, slashIndex);
  const targetPath = pathVal.slice(slashIndex);

  return { url: `https://${targetHost}${targetPath}${searchPart}`, ok: true };
}

function log(ev: Record<string, unknown>): void {
  console.log(JSON.stringify(ev));
}

const HOP_BY_HOP = [
  'host',
  'proxy-authorization',
  'x-proxy-authorization',
  'content-length',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
];

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const pathVal = url.searchParams.get('path');
    const start = Date.now();

    if (pathVal === '' || pathVal === 'health') {
      return new Response('ok', { status: 200 });
    }

    ensureAuth();
    if (!checkAuth(request)) return challengeAuth();

    const { url: targetUrl, ok } = buildTargetUrl(request.url);
    if (!ok) {
      return new Response('Path must be /<host>/<path>', { status: 400 });
    }

    const headers = new Headers(request.headers);
    for (const h of HOP_BY_HOP) headers.delete(h);

    const init: RequestInit = {
      method: request.method,
      headers,
      redirect: 'manual',
      signal: AbortSignal.any([
        request.signal,
        AbortSignal.timeout(FETCH_TTFT_TIMEOUT_MS),
      ]),
    };
    if (request.method !== 'GET' && request.method !== 'HEAD' && request.body) {
      init.body = request.body;
      (init as RequestInit & { duplex: 'half' }).duplex = 'half';
    }

    try {
      const upstream = await fetch(targetUrl, init);
      log({
        ev: 'proxy_ok',
        method: request.method,
        path: url.pathname,
        upstream: targetUrl,
        status: upstream.status,
        ttft_ms: Date.now() - start,
      });
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: upstream.headers,
      });
    } catch (err) {
      const e = err as Error;
      const msg = e.message || String(err);
      const isAbort = e.name === 'AbortError' || /abort|timeout/i.test(msg);
      log({
        ev: isAbort ? 'proxy_abort' : 'proxy_err',
        method: request.method,
        path: url.pathname,
        upstream: targetUrl,
        status: isAbort ? 504 : 502,
        ms: Date.now() - start,
        err: msg,
      });
      return new Response(`Proxy error: ${msg}`, { status: isAbort ? 504 : 502 });
    }
  },
};
