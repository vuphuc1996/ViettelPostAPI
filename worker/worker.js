/**
 * Viettel Post API Desk - CORS gateway
 * Routes: /dev/v2/... and /prod/v2/...
 * No credentials are stored. Requests are forwarded only to the two official
 * Viettel Post origins and only for the explicit allow-list below.
 */
const ALLOWED_ORIGINS = new Set([
  'https://vuphuc1996.github.io',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:8000',
  'http://127.0.0.1:8000'
]);
const BASE = {
  dev: 'https://partnerdev.viettelpost.vn',
  prod: 'https://partner.viettelpost.vn'
};
const ALLOWED = new Map([
  ['POST /v2/user/Login', true],
  ['POST /v2/user/ownerconnect', true],
  ['POST /v2/user/LoginVTP', true],
  ['GET /v2/categories/listProvince', true],
  ['GET /v2/categories/listDistrict', true],
  ['GET /v2/categories/listWards', true],
  ['POST /v2/order/getPriceAll', true],
  ['POST /v2/order/getPrice', true],
  ['POST /v2/order/getPriceAllNlp', true],
  ['POST /v2/order/getPriceNlp', true],
  ['POST /v2/order/createOrderNlp', true],
  ['GET /v2/order/getOrderDetailV3', true],
  ['GET /v2/user/listInventory', true]
]);
const MAX_BODY_BYTES = 1024 * 1024;

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Token, Accept',
    'Access-Control-Max-Age': '600',
    'Vary': 'Origin',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  };
}
function json(data, status, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=UTF-8', ...headers }
  });
}
function parseRoute(url) {
  const match = url.pathname.match(/^\/(dev|prod)(\/.*)$/);
  if (!match) return null;
  const env = match[1];
  const pathname = match[2];
  if (!pathname.startsWith('/v2/') || pathname.includes('..') || /%2f|%5c/i.test(pathname)) return null;
  return { env, pathname, target: new URL(BASE[env] + pathname) };
}
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return json({ ok: true, service: 'Viettel Post API Desk CORS gateway', environments: Object.keys(BASE), allowListOnly: true }, 200, { 'Cache-Control': 'no-store' });
    }
    const origin = request.headers.get('Origin') || '';
    if (!ALLOWED_ORIGINS.has(origin)) {
      return json({ ok: false, error: true, message: 'Origin is not allowed by this CORS gateway.' }, 403, { 'Vary': 'Origin', 'Cache-Control': 'no-store' });
    }
    const route = parseRoute(url);
    if (!route) return json({ ok: false, error: true, message: 'Expected /dev/v2/... or /prod/v2/... route.' }, 400, corsHeaders(origin));
    const method = request.method.toUpperCase();
    if (method === 'OPTIONS') {
      const requestedMethod = (request.headers.get('Access-Control-Request-Method') || '').toUpperCase();
      const allowedMethod = ALLOWED.has(`${requestedMethod} ${route.pathname}`);
      if (!allowedMethod) return json({ ok: false, error: true, message: 'This endpoint/method is not enabled in the gateway allow-list.' }, 403, corsHeaders(origin));
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }
    if (!['GET', 'POST'].includes(method) || !ALLOWED.has(`${method} ${route.pathname}`)) {
      return json({ ok: false, error: true, message: 'This endpoint/method is not enabled in the gateway allow-list.' }, 403, corsHeaders(origin));
    }
    let bodyText = '';
    if (method === 'POST') {
      const contentLength = Number(request.headers.get('Content-Length') || 0);
      if (contentLength > MAX_BODY_BYTES) return json({ ok: false, error: true, message: 'Request body exceeds the 1 MB limit.' }, 413, corsHeaders(origin));
      bodyText = await request.text();
      if (new TextEncoder().encode(bodyText).byteLength > MAX_BODY_BYTES) return json({ ok: false, error: true, message: 'Request body exceeds the 1 MB limit.' }, 413, corsHeaders(origin));
      if (bodyText && !/^application\/json\b/i.test(request.headers.get('Content-Type') || '')) {
        return json({ ok: false, error: true, message: 'POST requests must use Content-Type application/json.' }, 415, corsHeaders(origin));
      }
    }
    const upstreamHeaders = new Headers();
    const contentType = request.headers.get('Content-Type');
    const accept = request.headers.get('Accept');
    const token = request.headers.get('Token');
    if (contentType) upstreamHeaders.set('Content-Type', contentType);
    else if (method === 'POST') upstreamHeaders.set('Content-Type', 'application/json;charset=UTF-8');
    if (accept) upstreamHeaders.set('Accept', accept);
    if (token) upstreamHeaders.set('Token', token);
    // The official ownerconnect example uses SERVERID=A. Never accept a caller-supplied Cookie.
    if (route.pathname === '/v2/user/ownerconnect') upstreamHeaders.set('Cookie', 'SERVERID=A');
    for (const [key, value] of url.searchParams) route.target.searchParams.append(key, value);
    try {
      const upstream = await fetch(route.target.toString(), {
        method,
        headers: upstreamHeaders,
        body: method === 'POST' ? (bodyText || '{}') : undefined,
        redirect: 'manual',
        cf: { cacheTtl: 0, cacheEverything: false }
      });
      const responseHeaders = corsHeaders(origin);
      const type = upstream.headers.get('Content-Type');
      if (type) responseHeaders['Content-Type'] = type;
      const requestId = upstream.headers.get('X-Request-Id');
      if (requestId) responseHeaders['X-Request-Id'] = requestId;
      const textBody = await upstream.text();
      // Do not proxy redirects, cookies, or upstream CORS headers to the browser.
      if (upstream.status >= 300 && upstream.status < 400) {
        return json({ ok: false, error: true, message: 'The upstream returned a redirect; automatic redirects are disabled in this gateway.' }, 502, responseHeaders);
      }
      return new Response(textBody || null, { status: upstream.status, headers: responseHeaders });
    } catch (error) {
      // Do not log or echo user credentials, token headers, or request body.
      return json({ ok: false, error: true, message: 'Upstream request failed. Verify Viettel Post availability and gateway deployment.' }, 502, corsHeaders(origin));
    }
  }
};
