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
  maxDuration: 300, // Vercel Hobby Node maxDuration 300s (default + max); Pro 300s default 可配 800s
};

// TTFT 仅作首响兜底（5s 内未首响 → 主动 504，便于上游 failover / key rotate）。
// 首响后透传流式 body 不限时，受 maxDuration 300s wall 管控。
const FETCH_TTFT_TIMEOUT_MS = 30_000;

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
  'user-agent',
];

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const pathVal = url.searchParams.get('path');
    const start = Date.now();

    if (pathVal === '' || pathVal === 'health' || !pathVal.includes('/')) {
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

    // 透传 client UA: gorouter 注入 X-Forwarded-User-Agent → 改写 user-agent 给上游
    const fwdUa = request.headers.get('x-forwarded-user-agent');
    if (fwdUa) headers.set('user-agent', fwdUa);

    const ttftController = new AbortController();
    const ttftTimer = setTimeout(() => ttftController.abort(), FETCH_TTFT_TIMEOUT_MS);
    const init: RequestInit = {
      method: request.method,
      headers,
      redirect: 'manual',
      signal: AbortSignal.any([request.signal, ttftController.signal]),
    };
    if (request.method !== 'GET' && request.method !== 'HEAD' && request.body) {
      init.body = request.body;
      (init as RequestInit & { duplex: 'half' }).duplex = 'half';
    }

    try {
      log({ ev: 'proxy_outgoing', ua: headers.get('user-agent') });
      const upstream = await fetch(targetUrl, init);
      clearTimeout(ttftTimer);
      const ttftMs = Date.now() - start;
      log({
        ev: 'proxy_stream_open',
        method: request.method,
        path: url.pathname,
        upstream: targetUrl,
        status: upstream.status,
        ttft_ms: ttftMs,
      });

      const outHeaders = new Headers(upstream.headers);
      outHeaders.set('x-accel-buffering', 'no');
      outHeaders.set('Cache-Control', 'no-cache');
      if (!outHeaders.get('content-type')) {
        outHeaders.set('content-type', 'text/event-stream');
      }

      const pipeController = new AbortController();
      if (request.signal) {
        if (request.signal.aborted) {
          pipeController.abort();
        } else {
          request.signal.addEventListener('abort', () => pipeController.abort(), { once: true });
        }
      }
      const STALL_TIMEOUT_MS = 30_000;
      let firstChunk = true;
      let stallTimer: ReturnType<typeof setTimeout> | null = null;
      const armStall = () => {
        if (stallTimer) clearTimeout(stallTimer);
        stallTimer = setTimeout(() => pipeController.abort(), STALL_TIMEOUT_MS);
      };
      armStall();
      const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, ctrl) {
          if (firstChunk) {
            log({ ev: 'proxy_stream_first_chunk', ms: Date.now() - start });
            firstChunk = false;
          }
          armStall();
          ctrl.enqueue(chunk);
        },
      });
      upstream.body!.pipeTo(writable, { signal: pipeController.signal })
        .then(() => {
          if (stallTimer) clearTimeout(stallTimer);
          log({ ev: 'proxy_stream_close', ms: Date.now() - start, ok: true });
        })
        .catch((e) => {
          if (stallTimer) clearTimeout(stallTimer);
          log({ ev: 'proxy_stream_close', ms: Date.now() - start, ok: false, err: (e as Error)?.message || String(e) });
        });

      return new Response(readable, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: outHeaders,
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
