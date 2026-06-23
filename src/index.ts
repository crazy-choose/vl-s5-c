// s5-vercel: CF Workers 兼容 fallback
// 实际部署走 api/proxy.ts (Node)
// 此文件保留为回退 / 参考

const FETCH_TTFT_TIMEOUT_MS = 30_000;
const STALL_TIMEOUT_MS = 30_000;

const PROXY_AUTH = new Map<string, string>();
let authInitialized = false;

function ensureAuth(env: Record<string, string>): void {
  if (authInitialized) return;
  if (env.PROXY_USER) PROXY_AUTH.set(env.PROXY_USER, env.PROXY_PASS || '');
  authInitialized = true;
}

function checkAuth(request: Request, env: Record<string, string>): boolean {
  if (!env.PROXY_USER) return true;
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

function buildTargetUrl(requestUrl: string): { url: string; targetHost: string; ok: boolean } {
  const u = new URL(requestUrl);
  const stripped = u.pathname.startsWith('/') ? u.pathname.slice(1) : u.pathname;
  const slashIndex = stripped.indexOf('/');
  if (slashIndex === -1) return { url: '', targetHost: '', ok: false };
  const targetHost = stripped.slice(0, slashIndex);
  const targetPath = stripped.slice(slashIndex);
  const searchPart = u.search || '';
  return { url: `https://${targetHost}${targetPath}${searchPart}`, targetHost, ok: true };
}

function log(ev: Record<string, unknown>): void {
  console.log(JSON.stringify(ev));
}

// ---- 请求侧: 白名单转发 ----
const FORWARD_ALLOW = new Set([
  'authorization',
  'content-type',
  'content-length',
  'accept',
  'accept-language',
  'host',
  'user-agent',
]);

// ---- 响应侧: 只删 hop-by-hop ----
const RES_HOP_BY_HOP = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
];

export default {
  async fetch(request: Request, env: Record<string, string>): Promise<Response> {
    try {
      return await handle(request, env);
    } catch (err) {
      const e = err as Error;
      const msg = e?.message || String(err);
      const stack = e?.stack || '';
      console.error('proxy_top_err', JSON.stringify({ msg, stack, url: request.url }));
      return new Response(`Proxy error: ${msg}`, { status: 502 });
    }
  },
};

async function handle(request: Request, env: Record<string, string>): Promise<Response> {
  const url = new URL(request.url);
  const start = Date.now();
  const stripped = url.pathname.startsWith('/') ? url.pathname.slice(1) : url.pathname;

  if (!stripped || !stripped.includes('/')) {
    return new Response('ok', { status: 200 });
  }

  ensureAuth(env);
  if (!checkAuth(request, env)) return challengeAuth();

  const { url: targetUrl, targetHost, ok } = buildTargetUrl(request.url);
  if (!ok) return new Response('Path must be /<host>/<path>', { status: 400 });

  // 白名单模式: 只转发上游需要的标准头
  const headers = new Headers();
  for (const [k, v] of request.headers.entries()) {
    if (FORWARD_ALLOW.has(k)) headers.set(k, v);
  }
  headers.set('host', targetHost);

  const fwdUa = request.headers.get('x-forwarded-user-agent');
  if (fwdUa) headers.set('user-agent', fwdUa);
  if (!headers.has('accept')) headers.set('accept', 'text/event-stream');

  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: 'follow',
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
    const fwdKeys: string[] = [];
    for (const k of headers.keys()) fwdKeys.push(k);
    log({ ev: 'proxy_outgoing', target: targetUrl, method: request.method, host: headers.get('host'), fwd_headers: fwdKeys });
    const upstream = await fetch(targetUrl, init);
    const ttft = Date.now() - start;

    const outHeaders = new Headers(upstream.headers);
    for (const h of RES_HOP_BY_HOP) outHeaders.delete(h);
    outHeaders.set('cache-control', 'no-store');
    if (!outHeaders.get('content-type')) {
      outHeaders.set('content-type', 'text/event-stream');
    }

    log({ ev: 'proxy_upstream_response', status: upstream.status, hasBody: !!upstream.body, ct: upstream.headers.get('content-type'), cl: upstream.headers.get('content-length'), ttft_ms: ttft });

    if (!upstream.body) {
      const text = await upstream.text();
      log({ ev: 'proxy_stream_close', ms: Date.now() - start, ok: true, empty: true, preview: text.slice(0, 300) });
      return new Response(null, { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
    }

    // Stall watchdog: 每帧重置
    const pipeController = new AbortController();
    if (request.signal) {
      if (request.signal.aborted) {
        pipeController.abort();
      } else {
        request.signal.addEventListener('abort', () => pipeController.abort(), { once: true });
      }
    }

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
          log({ ev: 'proxy_stream_first_chunk', ms: Date.now() - start, len: chunk.length });
          firstChunk = false;
        }
        armStall();
        ctrl.enqueue(chunk);
      },
    });

    upstream.body.pipeTo(writable, { signal: pipeController.signal })
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
      upstream: targetUrl,
      status: isAbort ? 504 : 502,
      ms: Date.now() - start,
      err: msg,
    });
    return new Response(`Proxy error: ${msg}`, { status: isAbort ? 504 : 502 });
  }
}
