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

// TTFT 仅作首响兜底（90s 内未首响 → 主动 504，便于上游 failover / key rotate）。
// 首响后透传流式 body 不限时，受 maxDuration 300s wall 管控。
// 2026-06-24: 45→90s, nvidia tthok 慢 key 78s 响应, 45s 卡边界必 abort
const FETCH_TTFT_TIMEOUT_MS = 90_000;
// 2026-06-24: 30→61s, GLM-5.1 流式帧间隔超 30s 触发 stall abort
const STALL_TIMEOUT_MS = 61_000;

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

function buildTargetUrl(requestUrl: string): { url: string; targetHost: string; ok: boolean } {
  const url = new URL(requestUrl);
  const pathVal = url.searchParams.get('path');
  if (!pathVal) {
    return { url: '', targetHost: '', ok: false };
  }

  const upstreamParams = new URLSearchParams(url.search);
  upstreamParams.delete('path');
  const searchStr = upstreamParams.toString();
  const searchPart = searchStr ? `?${searchStr}` : '';

  const slashIndex = pathVal.indexOf('/');
  if (slashIndex === -1) {
    return { url: '', targetHost: '', ok: false };
  }

  const targetHost = pathVal.slice(0, slashIndex);
  const targetPath = pathVal.slice(slashIndex);

  return { url: `https://${targetHost}${targetPath}${searchPart}`, targetHost, ok: true };
}

function log(ev: Record<string, unknown>): void {
  console.log(JSON.stringify(ev));
}

// ---- 请求侧: 白名单转发, 只传上游需要的标准头 ----
// Bug 7: 黑名单模式漏删 Vercel/gorouter 注入的非标准头 (x-vercel-* 等),
// 这些头发到 AI API → 触发对方 WAF/API gateway → 静默丢弃 POST → 30s timeout
const FORWARD_ALLOW = new Set([
  'authorization',
  'content-type',
  'content-length',
  'accept',
  'accept-language',
  'host',
  'user-agent',
]);

// ---- 响应侧: 只删 hop-by-hop, 保留 content-length ----
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
  async fetch(request: Request): Promise<Response> {
    try {
      return await handle(request);
    } catch (err) {
      const e = err as Error;
      const msg = e?.message || String(err);
      const stack = e?.stack || '';
      console.error('proxy_top_err', JSON.stringify({ msg, stack, url: request.url }));
      return new Response(`Proxy error: ${msg}`, { status: 502 });
    }
  },
};

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const pathVal = url.searchParams.get('path');
  const start = Date.now();

  if (pathVal === '' || pathVal === 'health' || !pathVal?.includes('/')) {
    return new Response('ok', { status: 200 });
  }

  ensureAuth();
  if (!checkAuth(request)) return challengeAuth();

  const { url: targetUrl, targetHost, ok } = buildTargetUrl(request.url);
  if (!ok) {
    return new Response('Path must be /<host>/<path>', { status: 400 });
  }

  // 白名单模式: 只转发上游需要的标准头, 避免转发 Vercel/gorouter 注入的杂头
  const headers = new Headers();
  for (const [k, v] of request.headers.entries()) {
    if (FORWARD_ALLOW.has(k)) headers.set(k, v);
  }
  headers.set('host', targetHost);

  // 透传 client UA: gorouter 注入 X-Forwarded-User-Agent → 改写 user-agent 给上游
  const fwdUa = request.headers.get('x-forwarded-user-agent');
  if (fwdUa) headers.set('user-agent', fwdUa);
  if (!headers.has('accept')) headers.set('accept', 'text/event-stream');

  const ttftController = new AbortController();
  const ttftTimer = setTimeout(() => ttftController.abort(), FETCH_TTFT_TIMEOUT_MS);
  const signals: AbortSignal[] = [];
  if (request.signal) signals.push(request.signal);
  signals.push(ttftController.signal);
  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: 'follow',
    signal: signals.length > 1 ? AbortSignal.any(signals) : signals[0],
  };

  // Vercel Node runtime: 流式 request.body + duplex:'half' 上传不可靠,
  // 大 body 时 upstream 收不到完整请求 → 0 frames / 超时. 先 buffer.
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const bodyBuf = await request.arrayBuffer();
    init.body = bodyBuf;
    headers.set('content-length', String(bodyBuf.byteLength));
  }

  try {
    const fwdKeys: string[] = [];
    for (const k of headers.keys()) fwdKeys.push(k);
    log({ ev: 'proxy_outgoing', target: targetUrl, method: request.method, host: headers.get('host'), fwd_headers: fwdKeys });
    const upstream = await fetch(targetUrl, init);
    clearTimeout(ttftTimer);
    const ttftMs = Date.now() - start;

    const outHeaders = new Headers(upstream.headers);
    for (const h of RES_HOP_BY_HOP) outHeaders.delete(h);
    outHeaders.set('x-accel-buffering', 'no');
    outHeaders.set('cache-control', 'no-store');
    if (!outHeaders.get('content-type')) {
      outHeaders.set('content-type', 'text/event-stream');
    }

    log({
      ev: 'proxy_upstream_response',
      method: request.method,
      upstream: targetUrl,
      status: upstream.status,
      hasBody: !!upstream.body,
      ct: upstream.headers.get('content-type'),
      cl: upstream.headers.get('content-length'),
      ttft_ms: ttftMs,
    });

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
    clearTimeout(ttftTimer);
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
