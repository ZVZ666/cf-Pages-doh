const DOH_URL = 'https://security.cloudflare-dns.com/dns-query'; // 上游 DoH 服务器 按需修改
const DNS_PATH = '/dns-query';                                    // 自定义 DNS 路径 推荐修改
const KV = 'DNS_KV';                                             //  KV 命名空间变量名
const UPDATE_INTERVAL = 86400000;                                 // 广告规则更新间隔 (毫秒) 默认 24 小时

// 环境变量：
//   CUSTOM_DNS：自定义解析，逗号分隔，示例:  "域名 IP"（如 example.com 192.168.0.1,example.net 127.0.0.1）
//   ADLIST_URLS：广告规则地址，逗号分隔 示例:  https://example.com/all.txt,https://example.com/hosts.txt
//   BLOCK_IP：修改广告拦截返回 IP，默认 0.0.0.0

const CONTENT_TYPE_DNS = 'application/dns-message';
const CONTENT_TYPE_JSON = 'application/dns-json';
const ADLIST_KEY = 'adblock:set';
const ADLIST_META = 'adblock:meta';
const CONFIG_VERSION_KEY = 'config_version';

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  },
};

function isKvAvailable(env) {
  return env && env[KV] && typeof env[KV].get === 'function';
}

async function safeKvGet(kv, key) {
  try { return await kv.get(key); } catch (e) { return null; }
}

async function safeKvPut(kv, key, value) {
  try { await kv.put(key, value); return true; } catch (e) { return false; }
}

function isValidIP(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(part => /^\d+$/.test(part) && +part >= 0 && +part <= 255);
}

function parseCustomDns(text) {
  const map = new Map();
  for (const raw of (text || '').split(',')) {
    const line = raw.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length !== 2) continue;
    const [domain, ip] = parts;
    if (!domain || !isValidIP(ip)) continue;
    map.set(domain.toLowerCase(), ip);
  }
  return map;
}

let customCache = { map: null, time: 0 };

async function getCustomRules(env) {
  const now = Date.now();
  if (customCache.map && now - customCache.time < 30000) return customCache.map;
  const map = parseCustomDns(env.CUSTOM_DNS);
  customCache = { map, time: now };
  return map;
}

function parseAdRules(text) {
  const blockSet = new Set();
  const allowSet = new Set();
  for (const raw of text.split('\n')) {
    let line = raw.trim();
    if (!line || line.startsWith('!') || line.startsWith('#')) continue;
    try {
      let isAllow = false;
      if (line.startsWith('@@')) { isAllow = true; line = line.slice(2); }
      if (line.startsWith('||')) line = line.slice(2);
      else if (line.startsWith('|')) line = line.slice(1);
      line = line.split('^')[0].split('$')[0].split('*')[0];
      line = line.replace(/^https?:\/\//, '').replace(/^\/\//, '');
      line = line.replace(/\/.*$/, '');
      if (!/^[a-z0-9.-]+$/i.test(line)) continue;
      if (!line.includes('.')) continue;
      if (line.startsWith('.') || line.endsWith('.')) continue;
      (isAllow ? allowSet : blockSet).add(line.toLowerCase());
    } catch (e) {
      continue;
    }
  }
  return { blockSet, allowSet };
}

function matches(domain, ruleSet, exact = false) {
  const lower = domain.toLowerCase();
  if (ruleSet.has(lower)) return true;
  if (exact) return false;
  const parts = lower.split('.');
  while (parts.length > 1) {
    parts.shift();
    if (ruleSet.has(parts.join('.'))) return true;
  }
  return false;
}

async function initAdList(env) {
  if (!isKvAvailable(env)) return;
  const kv = env[KV];
  const sources = (env.ADLIST_URLS || '').split(',').map(s => s.trim()).filter(Boolean);
  const allTexts = [];
  if (sources.length > 0) {
    const results = await Promise.allSettled(
      sources.map(url =>
        fetch(url).then(r => r.ok ? r.text() : '').catch(e => { console.error(`fetch ${url} failed:`, e); return ''; })
      )
    );
    results.forEach(r => { if (r.status === 'fulfilled' && r.value) allTexts.push(r.value); });
  }
  const { blockSet, allowSet } = parseAdRules(allTexts.join('\n'));
  await safeKvPut(kv, ADLIST_KEY, JSON.stringify({ block: [...blockSet], allow: [...allowSet] }));
  await safeKvPut(kv, ADLIST_META, JSON.stringify({ updatedAt: Date.now(), count: blockSet.size + allowSet.size, sources }));
}

let adSetCache = null;

async function loadAdSet(env) {
  if (!isKvAvailable(env)) return { blockSet: new Set(), allowSet: new Set() };
  if (adSetCache) return adSetCache;
  const raw = await safeKvGet(env[KV], ADLIST_KEY);
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        adSetCache = { blockSet: new Set(parsed), allowSet: new Set() };
      } else {
        adSetCache = { blockSet: new Set(parsed.block || []), allowSet: new Set(parsed.allow || []) };
      }
    } catch (e) {
      adSetCache = { blockSet: new Set(), allowSet: new Set() };
    }
  } else {
    adSetCache = { blockSet: new Set(), allowSet: new Set() };
  }
  return adSetCache;
}

function adlistSignature(env) {
  return (env.ADLIST_URLS || '') + '|v3';
}

let syncCache = { sig: null, time: 0 };

async function ensureConfigSynced(env) {
  if (!isKvAvailable(env)) return;
  const now = Date.now();
  const sig = adlistSignature(env);
  if (syncCache.sig === sig && now - syncCache.time < 30000) return;
  const kv = env[KV];
  const storedSig = await safeKvGet(kv, CONFIG_VERSION_KEY);
  if (storedSig !== sig) {
    await initAdList(env);
    await safeKvPut(kv, CONFIG_VERSION_KEY, sig);
    adSetCache = null;
  }
  syncCache = { sig, time: now };
}

async function refreshAdListIfNeeded(env, ctx) {
  if (!isKvAvailable(env)) return;
  const metaRaw = await safeKvGet(env[KV], ADLIST_META);
  if (!metaRaw) return;
  try {
    const meta = JSON.parse(metaRaw);
    if (Date.now() - (meta.updatedAt || 0) >= UPDATE_INTERVAL) {
      ctx.waitUntil(initAdList(env));
    }
  } catch (e) {}
}

function buildJsonResponse(name, ip) {
  return Response.json({
    Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
    Question: [{ name, type: 1 }],
    Answer: [{ name, type: 1, TTL: 3600, data: ip }],
  });
}

function decodeDnsQuestion(view) {
  let labels = [], offset = 12, end = offset;
  while (true) {
    const len = view.getUint8(offset);
    if (len === 0) { offset++; end = offset; break; }
    if ((len & 0xC0) === 0xC0) { end = offset + 2; offset = ((len & 0x3F) << 8) | view.getUint8(offset + 1); continue; }
    labels.push(String.fromCharCode(...new Uint8Array(view.buffer, view.byteOffset + offset + 1, len)));
    offset += 1 + len; end = offset;
  }
  return { name: labels.join('.'), endOffset: end };
}

function buildWireResponse(reqBuffer, questionEndOffset, ip) {
  const view = new DataView(reqBuffer);
  const id = view.getUint16(0);
  const questionBytes = reqBuffer.slice(12, questionEndOffset);
  const [a, b, c, d] = ip.split('.').map(Number);
  const answer = new Uint8Array([0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04, a, b, c, d]);
  const header = new Uint8Array(12);
  const hv = new DataView(header.buffer);
  hv.setUint16(0, id); hv.setUint16(2, 0x8180); hv.setUint16(4, 1); hv.setUint16(6, 1);
  const response = new Uint8Array(12 + questionBytes.byteLength + answer.byteLength);
  response.set(header, 0);
  response.set(new Uint8Array(questionBytes), 12);
  response.set(answer, 12 + questionBytes.byteLength);
  return response.buffer;
}

async function serveStatic(env, request) {
  if (typeof env.ASSETS !== 'undefined') {
    const res = await env.ASSETS.fetch(new Request(request.url, { method: 'GET', headers: { 'Accept': 'text/html' } }));
    if (res.status !== 400) return res;
  }
  return fetch(new URL('/', request.url).href + 'index.html');
}


function shouldBlock(lower, blockSet, allowSet) {
  const isAllowed = matches(lower, allowSet, true);
  const isBlocked = matches(lower, blockSet, false);
  return !isAllowed && isBlocked;
}

async function handleDohRequest(request, env) {
  const { method, headers, url } = request;
  const { searchParams } = new URL(url);
  const custom = await getCustomRules(env);
  const { blockSet, allowSet } = await loadAdSet(env);
  const blockIP = env.BLOCK_IP || '0.0.0.0';

  if (method === 'GET' && (headers.get('Accept') === CONTENT_TYPE_JSON || searchParams.has('name'))) {
    const domain = searchParams.get('name');
    if (domain) {
      const lower = domain.toLowerCase();
      const customIP = custom.get(lower);
      if (customIP) return buildJsonResponse(domain, customIP);
      if (shouldBlock(lower, blockSet, allowSet)) return buildJsonResponse(domain, blockIP);
    }
    return fetch(`${DOH_URL}${new URL(url).search}`, { method: 'GET', headers: { 'Accept': CONTENT_TYPE_JSON } });
  }

  if (method === 'GET' && searchParams.has('dns')) {
    const b64 = searchParams.get('dns');
    const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
    const view = new DataView(bytes.buffer);
    const { name, endOffset } = decodeDnsQuestion(view);
    if (name) {
      const lower = name.toLowerCase();
      const customIP = custom.get(lower);
      if (customIP) return new Response(buildWireResponse(bytes.buffer, endOffset, customIP), { headers: { 'Content-Type': CONTENT_TYPE_DNS } });
      if (shouldBlock(lower, blockSet, allowSet)) return new Response(buildWireResponse(bytes.buffer, endOffset, blockIP), { headers: { 'Content-Type': CONTENT_TYPE_DNS } });
    }
    return fetch(`${DOH_URL}?dns=${searchParams.get('dns')}`, { method: 'GET', headers: { 'Accept': CONTENT_TYPE_DNS } });
  }

  if (method === 'POST' && headers.get('content-type') === CONTENT_TYPE_DNS) {
    const reqBuffer = await request.arrayBuffer();
    const view = new DataView(reqBuffer);
    const { name, endOffset } = decodeDnsQuestion(view);
    if (name) {
      const lower = name.toLowerCase();
      const customIP = custom.get(lower);
      if (customIP) return new Response(buildWireResponse(reqBuffer, endOffset, customIP), { headers: { 'Content-Type': CONTENT_TYPE_DNS } });
      if (shouldBlock(lower, blockSet, allowSet)) return new Response(buildWireResponse(reqBuffer, endOffset, blockIP), { headers: { 'Content-Type': CONTENT_TYPE_DNS } });
    }
    return fetch(DOH_URL, { method: 'POST', headers: { 'Accept': CONTENT_TYPE_DNS, 'Content-Type': CONTENT_TYPE_DNS }, body: reqBuffer });
  }

  return new Response(null, { status: 404 });
}

async function handleRequest(request, env, ctx) {
  await ensureConfigSynced(env);
  await refreshAdListIfNeeded(env, ctx);

  const { method, headers, url } = request;
  const { pathname, searchParams } = new URL(url);

  if (pathname === DNS_PATH) {
    const isDoh =
      (method === 'GET' && searchParams.has('dns')) ||
      (method === 'GET' && (headers.get('Accept') === CONTENT_TYPE_JSON || searchParams.has('name'))) ||
      (method === 'POST' && headers.get('content-type') === CONTENT_TYPE_DNS);
    if (isDoh) return handleDohRequest(request, env);
    return serveStatic(env, request);
  }
  return serveStatic(env, request);
}
