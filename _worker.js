const DOH_URL = 'https://security.cloudflare-dns.com/dns-query'; // 上游 DoH 服务器 按需修改
const DNS_PATH = '/dns-query';                                                    // 自定义 DNS 路径 推荐修改
const KV = 'DNS_KV';                                                                    // KV 命名空间变量名
const UPDATE_INTERVAL = 86400000;                                          // 广告规则更新间隔 (毫秒) 默认 24 小时
const ECS_ENABLED = true;                                                          // 是否透传 EDNS Client Subnet（ECS）
const ECS_DEFAULT_PREFIX_V4 = 24;                                           // IPv4 ECS 默认掩码前缀(0-32)
const ECS_DEFAULT_PREFIX_V6 = 56;                                           // IPv6 ECS 默认掩码前缀(0-128)

// 环境变量：
//   CUSTOM_DNS：自定义解析，逗号分隔，"域名 IP"（如 a.com 1.2.3.4,b.com 1.2.4.8）
//   ADLIST_URLS：广告规则地址，逗号分隔，支持 ||domain^ 与 @@||domain^ 放行规则
//   BLOCK_IP：广告拦截返回 IP，默认 0.0.0.0

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
        fetch(url, { signal: AbortSignal.timeout(30000) }).then(r => r.ok ? r.text() : '').catch(e => { console.error(`fetch ${url} failed:`, e); return ''; })
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
  return (env.ADLIST_URLS || '') + '|v4';
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

function buildJsonResponse(name, ip, ttl = 3600) {
  return Response.json({
    Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
    Question: [{ name, type: 1 }],
    Answer: [{ name, type: 1, TTL: ttl, data: ip }],
  });
}

function decodeDnsQuestion(view) {
  const len = view.byteLength;
  if (len < 12) return { name: '', endOffset: 12 };
  let labels = [], offset = 12, end = 12, jumps = 0;
  while (true) {
    if (offset >= len) return { name: labels.join('.'), endOffset: len };
    const b = view.getUint8(offset);
    if (b === 0) { offset++; end = offset; break; }
    if ((b & 0xC0) === 0xC0) {
      if (offset + 2 > len) return { name: labels.join('.'), endOffset: len };
      if (++jumps > 10) return { name: labels.join('.'), endOffset: offset + 2 }; 
      offset = ((b & 0x3F) << 8) | view.getUint8(offset + 1);
      continue;
    }
    if (b > 63) return { name: labels.join('.'), endOffset: offset + 1 };
    if (offset + 1 + b > len) return { name: labels.join('.'), endOffset: len };
    try {
      labels.push(String.fromCharCode(...new Uint8Array(view.buffer, view.byteOffset + offset + 1, b)));
    } catch (e) {
      labels.push('');
    }
    offset += 1 + b; end = offset;
  }
  return { name: labels.join('.'), endOffset: end + 4 };
}


function parseEcs(dnsBuffer) {
  const bytes = new Uint8Array(dnsBuffer);
  const view = new DataView(dnsBuffer);
  const len = bytes.byteLength;
  if (len < 12) return null;

  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);
  const nscount = view.getUint16(8);
  const arcount = view.getUint16(10);

  let off = 12;
  const skipName = () => {
    if (off >= len) return;
    const first = view.getUint8(off);
    if ((first & 0xC0) === 0xC0) { off += 2; return; }
    if (first === 0) { off += 1; return; }
    let jumps = 0;
    while (off < len && bytes[off] !== 0) {
      if ((bytes[off] & 0xC0) === 0xC0) { off += 2; break; }
      off += bytes[off] + 1;
      if (++jumps > 20) { off = len; return; }
    }
    if (off < len && bytes[off] === 0) off += 1;
  };

  for (let i = 0; i < qdcount && off < len; i++) { skipName(); off += 4; }

  const skipRR = () => {
    skipName();
    if (off + 8 > len) { off = len; return; }
    off += 8;
    if (off + 2 > len) { off = len; return; }
    const rdlen = view.getUint16(off); off += 2;
    if (off + rdlen > len) { off = len; return; }
    off += rdlen;
  };

  for (let i = 0; i < ancount && off < len; i++) skipRR();
  for (let i = 0; i < nscount && off < len; i++) skipRR();

  for (let i = 0; i < arcount && off < len; i++) {
    const rrStart = off;
    skipName();
    if (off + 8 > len) break;
    const type = view.getUint16(off); off += 2;
    off += 2; 
    off += 4;
    if (off + 2 > len) break;
    const rdlen = view.getUint16(off); off += 2;
    const rdEnd = off + rdlen;
    if (type !== 41) { off = rdEnd; continue; }
    let p = off;
    while (p + 4 <= rdEnd && p + 4 <= len) {
      const optCode = (bytes[p] << 8) | bytes[p + 1]; p += 2;
      const optLen = (bytes[p] << 8) | bytes[p + 1]; p += 2;
      const optEnd = p + optLen;
      if (optCode === 8 && optLen >= 4) { 
        if (optEnd > rdEnd || optEnd > len) break;
        const family = (bytes[p] << 8) | bytes[p + 1]; p += 2;
        const srcPrefix = bytes[p]; p += 1;
        const scopePrefix = bytes[p]; p += 1;
        if (family === 1 && optLen >= 8) {
          if (p + 4 <= optEnd) {
            const addr = `${bytes[p]}.${bytes[p + 1]}.${bytes[p + 2]}.${bytes[p + 3]}`;
            return { ip: addr, prefix: srcPrefix, scope: scopePrefix, family: 1 };
          }
        }
        if (family === 2 && optLen >= 20) {
          if (p + 16 <= optEnd) {
            const parts = [];
            for (let k = 0; k < 16; k += 2) parts.push(((bytes[p + k] << 8) | bytes[p + k + 1]).toString(16));
            return { ip: parts.join(':'), prefix: srcPrefix, scope: scopePrefix, family: 2 };
          }
        }
      }
      p = optEnd;
    }
    off = rdEnd;
  }
  return null;
}

function ipToBytes(ip) {
  if (!ip || typeof ip !== 'string') return new Uint8Array(4);
  const trimmed = ip.trim();
  if (trimmed.includes(':')) {
    try {
      let str = trimmed;
      if (str.includes('/')) str = str.split('/')[0];
      const expand = (seg) => (seg === '' ? [] : seg.split(':').map(x => {
        const n = parseInt(x, 16);
        return Number.isNaN(n) ? 0 : n;
      }));
      const parts = str.split('::');
      if (parts.length > 2) return new Uint8Array(16);
      let left = parts[0] ? expand(parts[0]) : [];
      let right = parts[1] ? expand(parts[1]) : [];
      if (left.length + right.length > 8) return new Uint8Array(16);
      const zeros = Math.max(0, 8 - left.length - right.length);
      const all = [...left, ...Array(zeros).fill(0), ...right];
      const result = new Uint8Array(16);
      for (let i = 0; i < 8; i++) {
        const v = all[i] || 0;
        if (v < 0 || v > 0xffff) return new Uint8Array(16);
        result[i * 2] = (v >> 8) & 0xff;
        result[i * 2 + 1] = v & 0xff;
      }
      return result;
    } catch (e) {
      return new Uint8Array(16);
    }
  }
  const ps = trimmed.split('.').map(p => parseInt(p, 10));
  if (ps.length !== 4 || ps.some(n => Number.isNaN(n) || n < 0 || n > 255)) {
    return new Uint8Array(4);
  }
  return Uint8Array.from(ps);
}

function defaultPrefixFor(ip) {
  if (!ip) return ECS_DEFAULT_PREFIX_V4;
  return ip.includes(':') ? ECS_DEFAULT_PREFIX_V6 : ECS_DEFAULT_PREFIX_V4;
}

function normalizeEcsSource(clientIp, defaultPrefix) {
  if (!clientIp) return null;
  const prefix = defaultPrefix != null ? defaultPrefix : defaultPrefixFor(clientIp);
  return { ip: clientIp, prefix };
}

function getClientIp(request) {
  const headers = request.headers;
  const cf = headers.get('CF-Connecting-IP');
  if (cf && /^[0-9a-fA-F:.]+$/.test(cf.trim())) return cf.trim();
  const xff = headers.get('X-Forwarded-For');
  if (xff) {
    const first = xff.split(',')[0].trim();
    if (/^[0-9a-fA-F:.]+$/.test(first)) return first;
  }
  return null;
}

function buildWireResponse(reqBuffer, questionEndOffset, ip, ttl = 3600) {
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
  if (env && env.ASSETS && typeof env.ASSETS.fetch === 'function') {
    const url = new URL(request.url);
    const origin = url.origin;

    if (url.pathname === '/' || url.pathname === '/index.html') {
      const direct = await env.ASSETS.fetch(
        new Request(url.href, { method: 'GET', redirect: 'manual' })
      ).catch(() => null);
      if (direct && direct.status === 200) return direct;
    }
    const rootRes = await env.ASSETS.fetch(
      new Request(origin + '/', { method: 'GET', redirect: 'manual' })
    ).catch(() => null);
    if (rootRes && rootRes.status === 200) {
      return new Response(rootRes.body, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    const idxRes = await env.ASSETS.fetch(
      new Request(origin + '/index.html', { method: 'GET', redirect: 'manual' })
    ).catch(() => null);
    if (idxRes && idxRes.status === 200) {
      return new Response(idxRes.body, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
  }

  return new Response(
    '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>DNS over HTTPS</title></head>' +
    '<body><h1>DNS over HTTPS</h1><p>请将 index.html 放在项目根目录。</p></body></html>',
    { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}

function shouldBlock(lower, blockSet, allowSet) {
  const isAllowed = matches(lower, allowSet, true);
  const isBlocked = matches(lower, blockSet, false);
  return !isAllowed && isBlocked;
}



function isEcsEnabled(env) {
  return String(env.ECS_ENABLED).toLowerCase() !== 'false';
}

function getEcsPrefix(env) {
  const p = Number(env.ECS_PREFIX);
  return Number.isInteger(p) && p >= 0 && p <= 32 ? p : ECS_DEFAULT_PREFIX_V4;
}

function concatBytes(arrays) {
  const total = arrays.reduce((s, a) => s + (a ? a.byteLength : 0), 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) { if (a && a.byteLength) { out.set(a, o); o += a.byteLength; } }
  return out;
}

function buildEcsOptionPayload(ip, prefix) {
  const isV6 = ip.includes(':');
  const family = isV6 ? 2 : 1;
  const addrBytes = ipToBytes(ip);
  const addrLen = isV6 ? 16 : 4;
  const optDataLen = 4 + addrLen;
  const buf = new Uint8Array(4 + optDataLen);
  const v = new DataView(buf.buffer);
  v.setUint16(0, 8); v.setUint16(2, optDataLen);
  v.setUint16(4, family);
  buf[6] = prefix & 0xff; buf[7] = 0;
  buf.set(addrBytes, 8);
  return buf;
}

function buildFullOptRr(ecsPayload) {
  const head = new Uint8Array(11);
  const v = new DataView(head.buffer);
  head[0] = 0; 
  v.setUint16(1, 41);
  v.setUint16(3, 1232);
  v.setUint32(5, 0);
  v.setUint16(9, ecsPayload.byteLength);
  return concatBytes([head, ecsPayload]);
}

function rebuildOptRr(dnsBuffer, optInfo, ecsPayload) {
  const bytes = new Uint8Array(dnsBuffer);
  const view = new DataView(dnsBuffer);

  const kept = [];
  let p = optInfo.rdStart;
  while (p + 4 <= optInfo.rdEnd && p + 4 <= bytes.length) {
    const code = (bytes[p] << 8) | bytes[p + 1];
    const olen = (bytes[p + 2] << 8) | bytes[p + 3];
    const optEnd = p + 4 + olen;
    if (optEnd > optInfo.rdEnd || optEnd > bytes.length) break;
    if (code !== 8) kept.push(bytes.slice(p, optEnd));
    p = optEnd;
  }
  const keptBytes = concatBytes(kept);
  const newRdata = concatBytes([keptBytes, ecsPayload]);
  const newRdLen = newRdata.byteLength;

  const head = new Uint8Array(11);
  const hv = new DataView(head.buffer);
  head[0] = 0; 
  hv.setUint16(1, 41); 
  if (optInfo.rrStart + 11 <= bytes.length) {
    hv.setUint16(3, view.getUint16(optInfo.rrStart + 3));
    hv.setUint32(5, view.getUint32(optInfo.rrStart + 5));
  } else {
    hv.setUint16(3, 1232);
    hv.setUint32(5, 0);
  }
  hv.setUint16(9, newRdLen);

  const beforeRr = bytes.slice(0, optInfo.rrStart);
  const afterRr = bytes.slice(optInfo.rdEnd);
  return concatBytes([beforeRr, head, newRdata, afterRr]).buffer;
}

function injectEcsToWire(dnsBuffer, ecs) {
  if (!ecs || !ecs.ip) return { buffer: dnsBuffer, hasEcs: false };
  const bytes = new Uint8Array(dnsBuffer);
  const view = new DataView(dnsBuffer);
  const len = bytes.byteLength;
  if (len < 12) return { buffer: dnsBuffer, hasEcs: false };

  let ecsPayload;
  try {
    ecsPayload = buildEcsOptionPayload(ecs.ip, ecs.prefix);
  } catch (e) {
    return { buffer: dnsBuffer, hasEcs: false };
  }

  let off = 12;
  const maxOff = len;

  const skipName = () => {
    if (off >= maxOff) return;
    const first = view.getUint8(off);
    if ((first & 0xC0) === 0xC0) { off = Math.min(off + 2, maxOff); return; }
    if (first === 0) { off = Math.min(off + 1, maxOff); return; }
    let jumps = 0;
    while (off < maxOff && bytes[off] !== 0) {
      if ((bytes[off] & 0xC0) === 0xC0) { off = Math.min(off + 2, maxOff); break; }
      const labelLen = bytes[off];
      if (labelLen > 63) { off = Math.min(off + 1, maxOff); break; }
      off = Math.min(off + 1 + labelLen, maxOff);
      if (++jumps > 20) { off = maxOff; return; }
    }
    if (off < maxOff && bytes[off] === 0) off = Math.min(off + 1, maxOff);
  };

  const qdcount = view.getUint16(4);
  for (let i = 0; i < qdcount && off < maxOff; i++) { skipName(); if (off + 4 <= maxOff) off += 4; }

  const skipRR = () => {
    skipName();
    if (off + 8 > maxOff) { off = maxOff; return; }
    off += 8; 
    if (off + 2 > maxOff) { off = maxOff; return; }
    const rdlen = view.getUint16(off); off += 2;
    if (off + rdlen > maxOff) { off = maxOff; return; }
    off += rdlen;
  };

  const ancount = view.getUint16(6);
  const nscount = view.getUint16(8);
  for (let i = 0; i < ancount && off < maxOff; i++) skipRR();
  for (let i = 0; i < nscount && off < maxOff; i++) skipRR();

  const arcount = view.getUint16(10);

  const rrInfos = [];
  for (let i = 0; i < arcount && off < maxOff; i++) {
    const rrStart = off;
    skipName();
    if (off + 8 > maxOff) break;
    off += 2;
    off += 2;
    off += 4; 
    if (off + 2 > maxOff) break;
    const rdlen = view.getUint16(off); off += 2;
    const rdStart = off;
    const rdEnd = Math.min(off + rdlen, maxOff);
    off = rdEnd;
    rrInfos.push({ rrStart, rdStart, rdEnd });
  }

  let optInfo = null;
  for (const info of rrInfos) {
    if (info.rrStart + 3 > bytes.length) continue;
    const type = (bytes[info.rrStart + 1] << 8) | bytes[info.rrStart + 2];
    if (type !== 41) continue;

    let p = info.rdStart;
    let hasEcs = false;
    while (p + 4 <= info.rdEnd && p + 4 <= bytes.length) {
      const code = (bytes[p] << 8) | bytes[p + 1];
      const olen = (bytes[p + 2] << 8) | bytes[p + 3];
      const optEnd = p + 4 + olen;
      if (optEnd > info.rdEnd || optEnd > bytes.length) break;
      if (code === 8) { hasEcs = true; break; }
      p = optEnd;
    }
    optInfo = { ...info, hasEcs };
    break;
  }

  if (optInfo && optInfo.hasEcs) {
    return { buffer: dnsBuffer, hasEcs: true };
  }

  if (optInfo && !optInfo.hasEcs) {
    try {
      return { buffer: rebuildOptRr(dnsBuffer, optInfo, ecsPayload), hasEcs: true };
    } catch (e) {
      return { buffer: dnsBuffer, hasEcs: false };
    }
  }

  try {
    const optRr = buildFullOptRr(ecsPayload);
    const out = new Uint8Array(len + optRr.byteLength);
    out.set(bytes, 0);
    out.set(optRr, len);
    new DataView(out.buffer).setUint16(10, arcount + 1);
    return { buffer: out.buffer, hasEcs: true };
  } catch (e) {
    return { buffer: dnsBuffer, hasEcs: false };
  }
}

async function forwardWire(request, env, dnsBuffer, ecs) {
  let buffer = dnsBuffer;
  try {
    const result = injectEcsToWire(dnsBuffer, ecs);
    buffer = result.buffer;
  } catch (e) {
    buffer = dnsBuffer;
  }
  return fetch(DOH_URL, {
    method: 'POST',
    headers: { 'Accept': CONTENT_TYPE_DNS, 'Content-Type': CONTENT_TYPE_DNS },
    body: buffer,
  });
}

async function handleDohRequest(request, env) {
  const { method, headers, url } = request;
  const { searchParams } = new URL(url);
  const custom = await getCustomRules(env);
  const { blockSet, allowSet } = await loadAdSet(env);
  const blockIP = env.BLOCK_IP || '0.0.0.0';
  const ecsEnabled = isEcsEnabled(env);

  const clientIp = getClientIp(request);
  const explicitEcs = (() => {
    if (!ecsEnabled) return null;
    const ecsRaw = searchParams.get('ecs');
    if (!ecsRaw) return null;
    const [ip, prefixStr] = ecsRaw.split('/');
    if (!ip) return null;
    const prefix = prefixStr != null ? Number(prefixStr) : defaultPrefixFor(ip);
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) && !ip.includes(':')) return null;
    if (Number.isNaN(prefix) || prefix < 0) return null;
    return { ip, prefix };
  })();
  const autoEcs = (!explicitEcs && ecsEnabled) ? normalizeEcsSource(clientIp, null) : null;
  const ecsForWire = explicitEcs || autoEcs || null;
  const jsonEcsParam = explicitEcs ? `${explicitEcs.ip}/${explicitEcs.prefix}` : (autoEcs ? `${autoEcs.ip}/${autoEcs.prefix}` : null);

  if (method === 'GET' && headers.get('Accept') === CONTENT_TYPE_JSON) {
    const domain = searchParams.get('name');
    if (domain) {
      const lower = domain.toLowerCase();
      const customIP = custom.get(lower);
      if (customIP) return buildJsonResponse(domain, customIP);
      if (shouldBlock(lower, blockSet, allowSet)) return buildJsonResponse(domain, blockIP);
    }
    const upstreamUrl = new URL(DOH_URL);
    searchParams.forEach((value, key) => {
      upstreamUrl.searchParams.set(key, value);
    });
    if (ecsEnabled && jsonEcsParam) {
      upstreamUrl.searchParams.set('ecs', jsonEcsParam);
    } else {
      upstreamUrl.searchParams.delete('ecs');
    }
    return fetch(upstreamUrl.toString(), { method: 'GET', headers: { 'Accept': CONTENT_TYPE_JSON } });
  }

  if (method === 'GET' && searchParams.has('dns')) {
    const b64 = searchParams.get('dns');
    const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
    if (bytes.byteLength < 12) {
      return fetch(`${DOH_URL}?dns=${searchParams.get('dns')}`, { method: 'GET', headers: { 'Accept': CONTENT_TYPE_DNS } });
    }
    const view = new DataView(bytes.buffer);
    const { name, endOffset } = decodeDnsQuestion(view);
    if (name) {
      const lower = name.toLowerCase();
      const customIP = custom.get(lower);
      if (customIP) return new Response(buildWireResponse(bytes.buffer, endOffset, customIP), { headers: { 'Content-Type': CONTENT_TYPE_DNS } });
      if (shouldBlock(lower, blockSet, allowSet)) return new Response(buildWireResponse(bytes.buffer, endOffset, blockIP), { headers: { 'Content-Type': CONTENT_TYPE_DNS } });
    }
    let parsed = null;
    try { parsed = ecsEnabled ? parseEcs(bytes.buffer) : null; } catch (e) {}
    const ecs = parsed || ecsForWire || null;
    if (ecs && ecs.ip) {
      const u = new URL(DOH_URL);
      u.searchParams.set('dns', searchParams.get('dns'));
      u.searchParams.set('ecs', `${ecs.ip}/${ecs.prefix}`);
      return fetch(u.toString(), { method: 'GET', headers: { 'Accept': CONTENT_TYPE_DNS } });
    }
    return fetch(`${DOH_URL}?dns=${searchParams.get('dns')}`, { method: 'GET', headers: { 'Accept': CONTENT_TYPE_DNS } });
  }

  if (method === 'POST' && headers.get('content-type') === CONTENT_TYPE_DNS) {
    let reqBuffer;
    try {
      reqBuffer = await request.arrayBuffer();
    } catch (e) {
      return new Response(null, { status: 400 });
    }
    if (reqBuffer.byteLength < 12) {
      return fetch(DOH_URL, { method: 'POST', headers: { 'Accept': CONTENT_TYPE_DNS, 'Content-Type': CONTENT_TYPE_DNS }, body: reqBuffer });
    }
    const view = new DataView(reqBuffer);
    const { name, endOffset } = decodeDnsQuestion(view);
    if (name) {
      const lower = name.toLowerCase();
      const customIP = custom.get(lower);
      if (customIP) return new Response(buildWireResponse(reqBuffer, endOffset, customIP), { headers: { 'Content-Type': CONTENT_TYPE_DNS } });
      if (shouldBlock(lower, blockSet, allowSet)) return new Response(buildWireResponse(reqBuffer, endOffset, blockIP), { headers: { 'Content-Type': CONTENT_TYPE_DNS } });
    }
    let parsed = null;
    try { parsed = ecsEnabled ? parseEcs(reqBuffer) : null; } catch (e) {}
    const ecs = parsed || ecsForWire || null;
    return forwardWire(request, env, reqBuffer, ecs);
  }

  return new Response(null, { status: 404 });
}

async function handleRequest(request, env, ctx) {
  try {
    await ensureConfigSynced(env);
    await refreshAdListIfNeeded(env, ctx);
  } catch (e) {}

  const { method, headers, url } = request;
  const { pathname, searchParams } = new URL(url);

  if (pathname === DNS_PATH) {
    const isDoh =
      (method === 'POST' && headers.get('content-type') === CONTENT_TYPE_DNS) ||
      (method === 'GET' && searchParams.has('dns')) ||
      (method === 'GET' && headers.get('Accept') === CONTENT_TYPE_JSON);
    if (isDoh) {
      try {
        return await handleDohRequest(request, env);
      } catch (e) {
        const upstreamUrl = new URL(DOH_URL);
        searchParams.forEach((value, key) => {
          if (key !== 'dns') upstreamUrl.searchParams.set(key, value);
        });
        return fetch(upstreamUrl.toString(), { method: 'GET', headers: { 'Accept': CONTENT_TYPE_JSON } });
      }
    }
  }

  return serveStatic(env, request);
}
