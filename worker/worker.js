/**
 * Viettel Post API Desk - CORS gateway + inbound webhook receiver.
 * API proxy routes are environment-prefixed: /dev/v2/... or /prod/v2/...
 * Webhook receiver: POST /webhook/viettelpost
 *
 * Credentials are not persisted. Configure WEBHOOK_SECRET with Wrangler Secret.
 * The receiver logs status metadata only; it does not persist event history.
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
  ['POST /v2/order/getPriceAllNlp', true],
  ['POST /v2/order/getPriceNlp', true],
  ['POST /v2/order/createOrderNlp', true],
  ['POST /v2/order/printing-code', true],
  // Order-maintenance routes from the public Partner Swagger reference.
  // Verify current schema/status permissions with the Partner API document/account.
  ['POST /v2/order/UpdateOrder', true],
  ['POST /v2/order/checkEditOrderInfo', true],
  ['POST /v2/order/editOrderInfoV2', true],
  ['POST /v2/order/historyEditOrderInfo', true]
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
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function handleWebhook(request, env) {
  if (request.method !== 'POST') return json({ status: 405, error: true, message: 'Method not allowed', data: null }, 405);
  if (!/^application\/json\b/i.test(request.headers.get('Content-Type') || '')) {
    return json({ status: 415, error: true, message: 'Content-Type application/json is required', data: null }, 415);
  }
  const secret = String(env.WEBHOOK_SECRET || '');
  if (!secret) return json({ status: 503, error: true, message: 'Webhook receiver is not configured: set WEBHOOK_SECRET.', data: null }, 503);
  const length = Number(request.headers.get('Content-Length') || 0);
  if (length > MAX_BODY_BYTES) return json({ status: 413, error: true, message: 'Webhook body exceeds 1 MB.', data: null }, 413);
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) return json({ status: 413, error: true, message: 'Webhook body exceeds 1 MB.', data: null }, 413);
  let payload;
  try { payload = JSON.parse(raw || '{}'); }
  catch { return json({ status: 400, error: true, message: 'Invalid JSON body.', data: null }, 400); }
  const authHeader = String(request.headers.get('Authorization') || '').trim();
  const bearerValue = authHeader.replace(/^Bearer\s+/i, '');
  const customHeader = String(request.headers.get('X-Webhook-Secret') || '').trim();
  const bodySecret = typeof payload?.TOKEN === 'string' ? payload.TOKEN : '';
  if (![authHeader, bearerValue, customHeader, bodySecret].some(value => safeEqual(value, secret))) {
    return json({ status: 401, error: true, message: 'Webhook authentication failed.', data: null }, 401);
  }
  const event = payload?.DATA || payload?.data || payload || {};
  const orderNumber = String(event.ORDER_NUMBER || event.orderNumber || '');
  const orderStatus = event.ORDER_STATUS ?? event.orderStatus ?? event.status ?? null;
  const orderStatusDate = String(event.ORDER_STATUSDATE || event.orderStatusDate || '');
  // Log identifiers/status metadata only. Never log complete payload, phone, address, or secret.
  console.log(JSON.stringify({
    event: 'viettelpost_webhook_received',
    orderNumber: orderNumber || null,
    orderStatus,
    orderStatusDate: orderStatusDate || null,
    receivedAt: new Date().toISOString()
  }));
  return json({ status: 200, error: false, message: 'OK', data: null }, 200, { 'Cache-Control': 'no-store' });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return json({ ok: true, service: 'Viettel Post API Desk Gateway', environments: Object.keys(BASE), allowListOnly: true, webhook: '/webhook/viettelpost', webhookSecretConfigured: !!env.WEBHOOK_SECRET }, 200, { 'Cache-Control': 'no-store' });
    }
    // Webhooks are server-to-server calls; do not require a browser Origin header.
    if (url.pathname === '/webhook/viettelpost') return handleWebhook(request, env);

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
    // The official ownerconnect example uses SERVERID=A. Never accept caller-supplied Cookie.
    if (route.pathname === '/v2/user/ownerconnect') upstreamHeaders.set('Cookie', 'SERVERID=A');
    // The public print-code integration sample uses SERVERID=2. Never accept caller-supplied Cookie.
    if (route.pathname === '/v2/order/printing-code') upstreamHeaders.set('Cookie', 'SERVERID=2');
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
      if (upstream.status >= 300 && upstream.status < 400) {
        return json({ ok: false, error: true, message: 'The upstream returned a redirect; automatic redirects are disabled in this gateway.' }, 502, responseHeaders);
      }
      return new Response(textBody || null, { status: upstream.status, headers: responseHeaders });
    } catch {
      return json({ ok: false, error: true, message: 'Upstream request failed. Verify Viettel Post availability and gateway deployment.' }, 502, corsHeaders(origin));
    }
  }
};
