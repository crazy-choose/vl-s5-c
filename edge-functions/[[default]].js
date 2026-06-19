/**
 * Vercel Edge Middleware — catch-all 代理
 * 路由: [[default]].js → 匹配所有路径
 * Edge 限制: 必须 25s 内 fetch resolve（起始响应），之后 streaming 最多 300s
 */

const FETCH_TTFT_TIMEOUT_MS = 25_000;

const PROXY_AUTH = new Map();
let authInitialized = false;

function ensureAuth(env) {
  if (authInitialized) return;
  if (env.PROXY_USER) PROXY_AUTH.set(env.PROXY_USER, env.PROXY_PASS || '');
  authInitialized = true;
}

function checkAuth(request, env) {
  if (!env.PROXY_USER) return true;
  const auth = request.headers.get('proxy-authorization');
  if (!auth?.startsWith('Basic ')) return false;
  const [user, pass] = atob(auth.slice(6)).split(':');
  return PROXY_AUTH.get(user) === pass;
}

function challengeAuth() {
  return new Response('Proxy Authentication Required', {
    status: 407,
    headers: { 'Proxy-Authenticate': 'Basic realm="Proxy"' },
  });
}

function buildTargetUrl(requestUrl) {
  const url = new URL(requestUrl);
  const parts = url.pathname.slice(1).split('/');
  if (parts.length < 2 || !parts[0]) {
    return { url: '', ok: false };
  }
  const targetHost = parts[0];
  const targetPath = '/' + parts.slice(1).join('/') + url.search;
  return { url: `https://${targetHost}${targetPath}`, ok: true };
}

function log(ev) {
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

export default function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const start = Date.now();

  if (url.pathname === '/' || url.pathname === '/health') {
    return new Response('ok', { status: 200 });
  }

  ensureAuth(env);
  if (!checkAuth(request, env)) return challengeAuth();

  const { url: targetUrl, ok } = buildTargetUrl(request.url);
  if (!ok) {
    return new Response('Path must be /<host>/<path>', { status: 400 });
  }

  const headers = new Headers(request.headers);
  for (const h of HOP_BY_HOP) headers.delete(h);

  const init = {
    method: request.method,
    headers,
    redirect: 'manual',
    signal: AbortSignal.any([
      request.signal,
      AbortSignal.timeout(FETCH_TTFT_TIMEOUT_MS),
    ]),
  };
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = request.body;
    init.duplex = 'half';
  }

  return fetch(targetUrl, init)
    .then((upstream) => {
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
    })
    .catch((err) => {
      const msg = err.message || String(err);
      const isAbort = err.name === 'AbortError' || /abort|timeout/i.test(msg);
      log({
        ev: isAbort ? 'proxy_abort' : 'proxy_err',
        method: request.method,
        path: url.pathname,
        upstream: targetUrl,
        status: isAbort ? 504 : 502,
        ms: Date.now() - start,
        err: msg,
      });
      return new Response('Proxy error: ' + msg, { status: isAbort ? 504 : 502 });
    });
}
