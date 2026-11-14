const DOH_URL = 'https://security.cloudflare-dns.com/dns-query';   // 上游 DoH 服务器 按需修改
// 备用上游列表，逗号分隔，主上游 5xx 或超时后按序尝试
const DOH_FALLBACKS = 'https://cloudflare-dns.com/dns-query,https://dns.quad9.net/dns-query';
const DNS_PATH = '/dns-query';                                     // 自定义 DNS 路径 推荐修改
const KV = 'DNS_KV';                                               // KV 命名空间变量名
const ECS_ENABLED = true;                                          // 是否透传 EDNS Client Subnet（ECS）
const ECS_PREFIX_V4 = 24;                                          // IPv4 ECS 默认掩码前缀(0-32)，0 表示不注入
const ECS_PREFIX_V6 = 56;                                          // IPv6 ECS 默认掩码前缀(0-128)
const BLOCK_IP = '0.0.0.0';                                        // 广告拦截返回 IPv4
const BLOCK_IP_V6 = '::';                                          // 广告拦截返回 IPv6
const ANSWER_TTL = 300;                                            // 自定义解析 TTL (秒)
const BLOCK_TTL = 60;                                              // 拦截应答 TTL (秒)
const UPDATE_INTERVAL = 86400000;                                  // 广告规则更新间隔 (毫秒) 默认 24 小时
const UPSTREAM_TIMEOUT = 4000;                                     // 上游超时 (毫秒)
const BOOT_WAIT = 1500;                                            // 冷启动等待规则加载上限 (毫秒)
const MAX_RULES = 300000;                                          // 单 isolate 规则条数上限
const MAX_BODY = 8192;                                             // wire 报文上限 (字节)
const RULES_FORMAT = 2;                                            // 规则存储格式版本，改格式时 +1
const EMPTY_RULES_TEXT = '\n';                                     // 空名单占位
const RULES_MEMORY_TTL = 60000;                                    // 内存规则缓存时间 (毫秒)
const META_CHECK_MS = 60000;                                       // 元信息检查间隔 (毫秒)
const RETRY_MS = 600000;                                           // 刷新失败退避 (毫秒)

// 环境变量：
//   CUSTOM_DNS：自定义解析，逗号分隔，"域名 IP"（如 a.com 1.2.3.4,b.com 1.2.4.8），子域继承
//   ADLIST_URLS：广告规则地址，逗号分隔，支持 ||domain^ 与 @@||domain^ 放行规则，清空即关闭过滤
//   BLOCK_IP：广告拦截返回 IP，默认 0.0.0.0
//   BLOCK_IP_V6：广告拦截返回 IPv6，默认 ::
//   ADBLOCK_ENABLED：是否启用域名拦截，默认 true
//   ANSWER_TTL / BLOCK_TTL：自定义解析与拦截应答的 TTL (秒)
//   ECS_PREFIX_V4 / ECS_PREFIX_V6：ECS 默认掩码前缀，设 0 表示不注入
//   DOH_URL / DOH_FALLBACKS：上游 DoH 与备用上游，逗号分隔
//   UPDATE_INTERVAL / UPSTREAM_TIMEOUT / BOOT_WAIT：刷新间隔、上游超时、冷启动等待 (毫秒)
//   TRUST_XFF：是否信任 X-Forwarded-For，默认 false
//
// KV 绑定名：DNS_KV（未绑定时自动降级为纯转发，DNS 功能不受影响）

const K_BLOCK = 'adblock:v2:block';   // 规则正文，纯文本一行一个域名
const K_ALLOW = 'adblock:v2:allow';   // 放行名单，同上
const K_META = 'adblock:meta';        // 同步状态 (JSON)
const K_LEGACY = 'adblock:set';       // 旧版 JSON 规则，兼容读取

const TYPE_A = 1;
const TYPE_AAAA = 28;
const TYPE_OPT = 41;
const CLASS_IN = 1;
const RCODE_SERVFAIL = 2;

export default {
  fetch: (request, env, ctx) => handleRequest(request, env, ctx),
  scheduled: (event, env, ctx) => {
    const state = ctx && typeof ctx.waitUntil === 'function' ? ctx : { waitUntil() {} };
    state.waitUntil(refreshRules(env, currentSig(env)).catch(err => {
      console.warn('[scheduled] refresh failed:', err && err.message);
    }));
  },
};

async function handleRequest(request, env, ctx) {
  const e = env || {};
  const cfg = resolveConfig(e);
  let url;
  try {
    url = new URL(request.url);
  } catch (err) {
    return new Response('bad request', { status: 400 });
  }
  const method = String(request.method || 'GET').toUpperCase();

  if (url.pathname !== cfg.dnsPath) return serveStatic(e, request);

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { ...corsHeaders(), 'access-control-max-age': '86400' } });
  }

  const safeCtx = ctx && typeof ctx.waitUntil === 'function'
    ? ctx
    : { waitUntil(p) { if (p && typeof p.catch === 'function') p.catch(() => {}); } };

  const rules = await ensureRules(e);
  safeCtx.waitUntil(maintenance(e, safeCtx).catch(err => console.warn('[maintain]', err && err.message)));

  try {
    if (method === 'POST' && (request.headers.get('content-type') || '').toLowerCase().startsWith('application/dns-message')) {
      return await handleWirePost(request, url, e, cfg, rules);
    }
    if (method === 'GET' && url.searchParams.has('dns')) {
      return await handleWireGet(request, url, e, cfg, rules);
    }
    if (method === 'GET' && (url.searchParams.has('name') || (request.headers.get('accept') || '').toLowerCase().includes('application/dns-json'))) {
      return await handleJsonGet(request, url, e, cfg, rules);
    }
    return badRequest('unsupported request');
  } catch (err) {
    console.warn('[doh] handler error:', err && err.stack ? err.stack.split('\n')[0] : err);
    return servfail(null);
  }
}

function opt(env, name, fallback) {
  const v = env[name];
  return v === undefined || v === null || String(v).trim() === '' ? fallback : v;
}

function optBool(env, name, fallback) {
  const v = opt(env, name, null);
  if (v === null) return fallback;
  const s = String(v).trim().toLowerCase();
  if (['false', '0', 'no', 'off'].includes(s)) return false;
  if (['true', '1', 'yes', 'on'].includes(s)) return true;
  return fallback;
}

function optInt(env, name, fallback, min, max) {
  const raw = opt(env, name, null);
  if (raw === null) return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  const v = Math.trunc(n);
  if (v < min || v > max) return fallback;
  return v;
}

function resolveConfig(env) {
  const shared = optInt(env, 'ECS_PREFIX', -1, -1, 128);
  return {
    dohUrl: String(opt(env, 'DOH_URL', DOH_URL)),
    fallbacks: String(opt(env, 'DOH_FALLBACKS', DOH_FALLBACKS)).split(',').map(s => s.trim()).filter(s => /^https?:\/\//i.test(s)),
    dnsPath: String(opt(env, 'DNS_PATH', DNS_PATH)),
    ecs: optBool(env, 'ECS_ENABLED', ECS_ENABLED),
    prefixV4: shared >= 0 ? Math.min(shared, 32) : optInt(env, 'ECS_PREFIX_V4', ECS_PREFIX_V4, 0, 32),
    prefixV6: shared >= 0 ? Math.min(shared, 128) : optInt(env, 'ECS_PREFIX_V6', ECS_PREFIX_V6, 0, 128),
    blockIp: String(opt(env, 'BLOCK_IP', BLOCK_IP)),
    blockIpV6: String(opt(env, 'BLOCK_IP_V6', BLOCK_IP_V6)),
    answerTtl: optInt(env, 'ANSWER_TTL', ANSWER_TTL, 0, 604800),
    blockTtl: optInt(env, 'BLOCK_TTL', BLOCK_TTL, 0, 604800),
    upstreamTimeout: optInt(env, 'UPSTREAM_TIMEOUT', UPSTREAM_TIMEOUT, 200, 25000),
    maxBody: optInt(env, 'MAX_BODY', MAX_BODY, 512, 65535),
    trustXff: optBool(env, 'TRUST_XFF', true),
  };
}

let kvWarned = false;

function kvAvailable(env) {
  const kv = env && env[KV];
  return !!kv && typeof kv.get === 'function' && typeof kv.put === 'function';
}

async function kvGet(kv, key) {
  try {
    return await kv.get(key);
  } catch (err) {
    console.warn(`[kv] get ${key} failed:`, err && err.message);
    return null;
  }
}

async function kvPut(kv, key, value) {
  try {
    await kv.put(key, value);
    return true;
  } catch (err) {
    console.warn(`[kv] put ${key} failed:`, err && err.message);
    return false;
  }
}

const EMPTY_RULES = { block: new Set(), allow: new Set() };

const rulesState = {
  rules: EMPTY_RULES,
  loaded: false,
  loading: null,
  sig: null,
  loadedAt: 0,
  checkedAt: 0,
  checkedSig: null,
  refreshing: null,
  retryAt: 0,
  retrySig: null,
};

function currentSig(env) {
  return `${String(opt(env, 'ADLIST_URLS', ''))}|${RULES_FORMAT}`;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function addAll(set, text) {
  if (!text) return;
  for (const line of String(text).split('\n')) {
    const v = line.trim();
    if (v) set.add(v);
  }
}

async function readRules(env) {
  const kv = env[KV];
  const rules = { block: new Set(), allow: new Set() };
  const [blockText, allowText, legacy] = await Promise.all([
    kvGet(kv, K_BLOCK),
    kvGet(kv, K_ALLOW),
    kvGet(kv, K_LEGACY),
  ]);

  // 空值也算已初始化，避免被旧格式数据复活
  if (blockText !== null || allowText !== null) {
    addAll(rules.block, blockText);
    addAll(rules.allow, allowText);
    return rules;
  }

  // 兼容旧版 JSON：{ block: [], allow: [] } 或裸数组
  if (legacy) {
    try {
      const parsed = JSON.parse(legacy);
      const block = Array.isArray(parsed) ? parsed : (parsed && parsed.block) || [];
      const allow = Array.isArray(parsed) ? [] : (parsed && parsed.allow) || [];
      for (const d of block) { const v = normalizeDomain(String(d)); if (v) rules.block.add(v); }
      for (const d of allow) { const v = normalizeDomain(String(d)); if (v) rules.allow.add(v); }
      console.log(`[rules] legacy format upgraded in memory: block=${rules.block.size} allow=${rules.allow.size}`);
    } catch (err) {
      console.warn('[rules] legacy parse failed:', err && err.message);
    }
  }
  return rules;
}

function loadRulesOnce(env, sig) {
  if (rulesState.loading) return rulesState.loading;
  rulesState.loading = readRules(env)
    .then(rules => {
      rulesState.rules = rules;
      rulesState.loaded = true;
      rulesState.sig = sig;
      rulesState.loadedAt = Date.now();
      return rules;
    })
    .catch(err => {
      console.warn('[rules] load failed:', err && err.message);
      return rulesState.rules;
    })
    .finally(() => {
      rulesState.loading = null;
    });
  return rulesState.loading;
}

async function ensureRules(env) {
  if (!kvAvailable(env)) {
    if (!kvWarned) {
      kvWarned = true;
      console.warn(`[kv] binding "${KV}" missing or incomplete — 本地规则功能已降级，DNS 转发不受影响`);
    }
    return EMPTY_RULES;
  }
  const sig = currentSig(env);
  const fresh = rulesState.loaded
    && rulesState.sig === sig
    && Date.now() - rulesState.loadedAt < RULES_MEMORY_TTL;
  if (fresh) return rulesState.rules;

  const pending = loadRulesOnce(env, sig);
  const wait = optInt(env, 'BOOT_WAIT', BOOT_WAIT, 0, 10000);
  if (wait <= 0) return rulesState.rules;

  const rules = await Promise.race([pending, sleep(wait)]);
  return rules || rulesState.rules;
}

async function readMeta(env) {
  const raw = await kvGet(env[KV], K_META);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (err) {
    console.warn('[meta] corrupt, ignoring:', err && err.message);
    return null;
  }
}

async function maintenance(env, ctx) {
  if (!kvAvailable(env)) return;
  const now = Date.now();
  const sig = currentSig(env);
  // 签名变化立即检查一次，其余按 META_CHECK_MS 节流
  if (rulesState.checkedSig === sig && now - rulesState.checkedAt < META_CHECK_MS) return;
  rulesState.checkedAt = now;
  rulesState.checkedSig = sig;
  if (rulesState.refreshing || (now < rulesState.retryAt && rulesState.retrySig === sig)) return;

  const meta = await readMeta(env);
  const interval = optInt(env, 'UPDATE_INTERVAL', UPDATE_INTERVAL, 60000, 30 * 86400000);
  const expired = !meta || meta.ok !== true || now - Number(meta.updatedAt || 0) >= interval;
  if (!expired && meta.sig === sig) return;

  rulesState.refreshing = refreshRules(env, sig).finally(() => {
    rulesState.refreshing = null;
  });
  ctx.waitUntil(rulesState.refreshing.catch(() => {}));
}

function parseSources(text) {
  return String(text || '')
    .split(/[,\n]/)
    .map(s => s.trim())
    .filter(s => /^https?:\/\//i.test(s));
}

async function fetchText(url) {
  const res = await fetch(url, {
    method: 'GET',
    headers: { accept: 'text/plain,*/*', 'user-agent': 'doh-worker/2.0' },
    signal: AbortSignal.timeout(30000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

async function refreshRules(env, sig) {
  if (!kvAvailable(env)) return false;
  const sources = parseSources(opt(env, 'ADLIST_URLS', ''));
  if (!sources.length) {
    // 没配列表即关闭过滤：清掉旧规则
    const had = rulesState.rules.block.size + rulesState.rules.allow.size;
    await Promise.all([
      kvPut(env[KV], K_BLOCK, EMPTY_RULES_TEXT),
      kvPut(env[KV], K_ALLOW, EMPTY_RULES_TEXT),
      kvPut(env[KV], K_META, JSON.stringify({
        ok: true, format: RULES_FORMAT, sig: currentSig(env), sources: [],
        block: 0, allow: 0, updatedAt: Date.now(),
      })),
    ]);
    rulesState.rules = { block: new Set(), allow: new Set() };
    rulesState.sig = currentSig(env);
    rulesState.loadedAt = Date.now();
    rulesState.loaded = true;
    rulesState.retryAt = 0;
    if (had) console.log(`[adlist] cleared ${had} rules: ADLIST_URLS is empty`);
    return true;
  }

  const results = await Promise.allSettled(sources.map(fetchText));
  const texts = [];
  const errors = [];
  results.forEach((r, i) => {
    if (r.status === 'fulfilled' && r.value) texts.push(r.value);
    else errors.push(`${sources[i]}: ${r.status === 'rejected' ? (r.reason && r.reason.message) || r.reason : 'empty body'}`);
  });

  if (!texts.length) {
    // 全源失败保留旧规则，只记录失败并退避
    console.warn('[adlist] all sources failed:', errors.join(' | '));
    await kvPut(env[KV], K_META, JSON.stringify({
      ok: false, format: RULES_FORMAT, sig: null, sources,
      updatedAt: Number(rulesState.loadedAt || 0), error: errors.join('; ').slice(0, 500),
    }));
    rulesState.retryAt = Date.now() + RETRY_MS;
    rulesState.retrySig = currentSig(env);
    return false;
  }

  const { block, allow, stats } = compileRules(texts);
  const ok = await Promise.all([
    kvPut(env[KV], K_BLOCK, [...block].join('\n')),
    kvPut(env[KV], K_ALLOW, [...allow].join('\n')),
    kvPut(env[KV], K_META, JSON.stringify({
      ok: true, format: RULES_FORMAT, sig, sources, updatedAt: Date.now(),
      block: block.size, allow: allow.size, skipped: stats.skipped, wildcard: stats.wildcard, lines: stats.lines,
      truncated: stats.truncated, failedSources: errors,
    })),
  ]);

  rulesState.rules = { block, allow };
  rulesState.loaded = true;
  rulesState.sig = sig;
  rulesState.loadedAt = Date.now();
  rulesState.retryAt = 0;
  console.log(`[adlist] refreshed block=${block.size} allow=${allow.size} skipped=${stats.skipped} lines=${stats.lines}`);
  return ok.every(Boolean);
}

const HOSTS_LINE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|::1?|0:0:0:0:0:0:0:1)\s+(\S.*)$/;
const DOMAIN_RE = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/;

function normalizeDomain(text) {
  let s = String(text || '').trim().toLowerCase();
  if (!s) return null;
  if (s.startsWith('*.')) s = s.slice(2);
  if (s.startsWith('.')) s = s.slice(1);
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (!s || s.length > 253) return null;
  if (!DOMAIN_RE.test(s)) return null;
  return s;
}

function addRule(rawLine, block, allow, stats) {
  let s = String(rawLine || '').trim();
  if (!s) return;
  if (s.startsWith('!') || s.startsWith('#') || s.startsWith('[')) return;

  const hosts = HOSTS_LINE.exec(s);
  if (hosts) {
    const rest = hosts[1].split('#')[0].trim();
    for (const token of rest.split(/\s+/)) {
      const d = normalizeDomain(token);
      if (d) block.add(d);
      else stats.skipped++;
    }
    return;
  }

  if (s.includes('##') || s.includes('#@#') || s.includes('#?#')) return;

  let isAllow = false;
  if (s.startsWith('@@')) { isAllow = true; s = s.slice(2); }

  s = s.split('$')[0];   // 去掉 $third-party 等选项
  s = s.split('#')[0];
  if (!s) return;

  if (s.startsWith('||')) s = s.slice(2);
  else if (s.startsWith('|')) s = s.slice(1);

  s = s.split('^')[0];
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/^\/\//, '');
  s = s.split('/')[0];
  if (!s || s.startsWith('~')) return;

  if (s.includes('*')) {
    const expanded = expandWildcardHost(s);
    if (!expanded) { stats.wildcard++; return; }
    s = expanded;
  }

  const d = normalizeDomain(s);
  if (!d) { stats.skipped++; return; }
  (isAllow ? allow : block).add(d);
}

// 整标签通配折叠为父域，标签内部分通配无法表达时返回 null
function expandWildcardHost(host) {
  const labels = String(host).split('.');
  const kept = [];
  for (let i = 0; i < labels.length; i++) {
    const label = labels[i];
    if (!label.includes('*')) { kept.push(label); continue; }
    if (label === '*' && i === 0) continue;   // *.a.com → a.com
    return null;
  }
  return kept.length ? kept.join('.') : null;
}

function compileRules(texts) {
  const block = new Set();
  const allow = new Set();
  const stats = { lines: 0, skipped: 0, wildcard: 0, truncated: false };
  outer:
  for (const text of texts) {
    if (!text) continue;
    for (const line of String(text).split('\n')) {
      if (block.size + allow.size >= MAX_RULES) {
        stats.truncated = true;
        break outer;
      }
      stats.lines++;
      addRule(line, block, allow, stats);
    }
  }
  return { block, allow, stats };
}

function matchesDomain(name, set) {
  if (!set || set.size === 0 || !name) return false;
  if (set.has(name)) return true;
  let idx = name.indexOf('.');
  while (idx >= 0) {
    if (set.has(name.slice(idx + 1))) return true;
    idx = name.indexOf('.', idx + 1);
  }
  return false;
}

// 放行优先，两者都按父域回溯
function decide(name, rules) {
  if (!name || !rules) return null;
  if (matchesDomain(name, rules.allow)) return 'allow';
  if (matchesDomain(name, rules.block)) return 'block';
  return null;
}

let customCache = { text: null, map: new Map() };

function parseCustomRules(text) {
  const map = new Map();
  for (const raw of String(text || '').split(/[,\n]/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    if (parts.length !== 2) continue;
    const domain = normalizeDomain(parts[0]);
    if (!domain) continue;
    const ip = parseIp(parts[1]);
    if (!ip) continue;
    const entry = map.get(domain) || { v4: [], v6: [] };
    const list = ip.family === 4 ? entry.v4 : entry.v6;
    if (!list.some(item => sameBytes(item.bytes, ip.bytes))) list.push(ip);
    map.set(domain, entry);
  }
  return map;
}

function getCustom(env) {
  const text = String(opt(env, 'CUSTOM_DNS', ''));
  if (customCache.text !== text) customCache = { text, map: parseCustomRules(text) };
  return customCache.map;
}

function lookupCustom(name, map) {
  if (!map || map.size === 0) return null;
  let s = name;
  for (;;) {
    const hit = map.get(s);
    if (hit) return hit;
    const idx = s.indexOf('.');
    if (idx < 0) return null;
    s = s.slice(idx + 1);
  }
}

function parseIPv4(text) {
  const parts = String(text || '').trim().split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(parts[i])) return null;
    const n = Number(parts[i]);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

function parseIPv6(text) {
  let s = String(text || '').trim();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  if (!s.includes(':')) return null;

  const tailStart = s.lastIndexOf(':') + 1;
  const tail = s.slice(tailStart);
  if (tail.includes('.')) {
    const v4 = parseIPv4(tail);
    if (!v4) return null;
    const g1 = (((v4[0] << 8) | v4[1]) >>> 0).toString(16);
    const g2 = (((v4[2] << 8) | v4[3]) >>> 0).toString(16);
    s = `${s.slice(0, tailStart)}${g1}:${g2}`;
  }

  if ((s.match(/::/g) || []).length > 1) return null;
  const chunks = s.split('::');
  const left = chunks[0] ? chunks[0].split(':') : [];
  const right = chunks.length > 1 ? (chunks[1] ? chunks[1].split(':') : []) : [];
  if (chunks.length === 1 && left.length !== 8) return null;
  if (chunks.length === 2 && left.length + right.length > 7) return null;

  const groups = [...left, ...right];
  for (const g of groups) if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;

  const out = new Uint8Array(16);
  const write = (g, i) => {
    const n = parseInt(g, 16);
    out[i * 2] = (n >> 8) & 0xff;
    out[i * 2 + 1] = n & 0xff;
  };
  if (chunks.length === 1) {
    groups.forEach(write);
    return out;
  }
  left.forEach(write);
  const offset = 8 - right.length;
  right.forEach((g, i) => write(g, offset + i));
  return out;
}

function parseIp(text) {
  if (typeof text !== 'string') return null;
  const s = text.trim();
  if (!s) return null;
  if (s.includes(':')) {
    const bytes = parseIPv6(s);
    return bytes ? { family: 6, bytes } : null;
  }
  const bytes = parseIPv4(s);
  return bytes ? { family: 4, bytes } : null;
}

function sameBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function formatIPv4(bytes) {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

function formatIPv6(bytes) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === '0') {
      if (curStart < 0) { curStart = i; curLen = 0; }
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen >= 2) {
    return `${groups.slice(0, bestStart).join(':')}::${groups.slice(bestStart + bestLen).join(':')}`;
  }
  return groups.join(':');
}

function formatIp(ip) {
  return ip.family === 6 ? formatIPv6(ip.bytes) : formatIPv4(ip.bytes);
}

// RFC 7871 §6：地址中前缀位之后必须置 0
function maskAddress(bytes, prefix) {
  const totalBits = bytes.length * 8;
  const bits = Math.max(0, Math.min(prefix | 0, totalBits));
  const out = bytes.slice();
  const full = bits >> 3;
  const rem = bits & 7;
  for (let i = full; i < out.length; i++) out[i] = 0;
  if (rem && full < out.length) out[full] &= (0xff << (8 - rem)) & 0xff;
  return out;
}

function latin1(bytes, start, len) {
  let out = '';
  for (let i = 0; i < len; i++) out += String.fromCharCode(bytes[start + i]);
  return out;
}

function asciiLower(text) {
  return text.replace(/[A-Z]+/g, m => m.toLowerCase());
}

function readName(bytes, start) {
  const labels = [];
  let off = start;
  let consumed = 0;
  let jumped = false;
  let jumps = 0;
  let length = 0;

  for (;;) {
    if (off >= bytes.length) return { name: labels.join('.'), end: start + consumed, ok: false };
    const len = bytes[off];

    if (len === 0) {
      if (!jumped) consumed += 1;
      break;
    }

    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= bytes.length) return { name: labels.join('.'), end: start + consumed, ok: false };
      const ptr = ((len & 0x3f) << 8) | bytes[off + 1];
      if (!jumped) consumed += 2;
      // 只允许向后指针，杜绝自环/前向环
      if (ptr >= off || ++jumps > 8) return { name: labels.join('.'), end: start + consumed, ok: false };
      jumped = true;
      off = ptr;
      continue;
    }

    if (len > 63 || off + 1 + len > bytes.length) {
      return { name: labels.join('.'), end: start + consumed, ok: false };
    }
    length += len + 1;
    if (length > 255) return { name: labels.join('.'), end: start + consumed, ok: false };
    labels.push(latin1(bytes, off + 1, len));
    if (!jumped) consumed += len + 1;
    off += len + 1;
  }

  return { name: labels.join('.'), end: start + consumed, ok: true };
}

function walkMessage(buffer) {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const msg = {
    bytes, view, len: bytes.length, ok: bytes.length >= 12,
    id: 0, flags: 0, qdcount: 0, ancount: 0, nscount: 0, arcount: 0,
    questions: [], questionEnd: 12, opt: null,
  };
  if (!msg.ok) return msg;

  msg.id = view.getUint16(0);
  msg.flags = view.getUint16(2);
  msg.qdcount = view.getUint16(4);
  msg.ancount = view.getUint16(6);
  msg.nscount = view.getUint16(8);
  msg.arcount = view.getUint16(10);

  let off = 12;
  for (let i = 0; i < msg.qdcount; i++) {
    const name = readName(bytes, off);
    if (!name.ok || name.end + 4 > bytes.length) { msg.ok = false; return msg; }
    msg.questions.push({
      name: name.name,
      lower: asciiLower(name.name),
      type: view.getUint16(name.end),
      cls: view.getUint16(name.end + 2),
      start: off,
      end: name.end + 4,
    });
    off = name.end + 4;
  }
  msg.questionEnd = off;

  const walkRR = () => {
    const rrStart = off;
    const name = readName(bytes, off);
    if (!name.ok || name.end + 10 > bytes.length) { msg.ok = false; return false; }
    const type = view.getUint16(name.end);
    const cls = view.getUint16(name.end + 2);
    const ttl = view.getUint32(name.end + 4);
    const rdlen = view.getUint16(name.end + 8);
    const rdStart = name.end + 10;
    const rdEnd = rdStart + rdlen;
    if (rdEnd > bytes.length) { msg.ok = false; return false; }

    if (type === TYPE_OPT) {
      if (msg.opt) { msg.ok = false; return false; }
      msg.opt = { rrStart, nameEnd: name.end, rdStart, rdEnd, cls, ttl, options: [] };
      let p = rdStart;
      while (p + 4 <= rdEnd) {
        const code = view.getUint16(p);
        const olen = view.getUint16(p + 2);
        const oEnd = p + 4 + olen;
        if (oEnd > rdEnd) { msg.ok = false; msg.opt = null; return false; }
        msg.opt.options.push({ code, len: olen, start: p, dataStart: p + 4, end: oEnd });
        p = oEnd;
      }
    }

    off = rdEnd;
    return true;
  };

  for (let i = 0; i < msg.ancount; i++) if (!walkRR()) return msg;
  for (let i = 0; i < msg.nscount; i++) if (!walkRR()) return msg;
  for (let i = 0; i < msg.arcount; i++) if (!walkRR()) return msg;
  return msg;
}

function concatBytes(parts) {
  let total = 0;
  for (const p of parts) total += p ? p.length : 0;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    if (p && p.length) { out.set(p, offset); offset += p.length; }
  }
  return out;
}

function exactBuffer(bytes) {
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) return bytes.buffer;
  return bytes.slice().buffer;
}

function toBase64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(text) {
  const b64 = String(text).replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function buildEcsPayload(ip, prefix) {
  const addr = maskAddress(ip.bytes, prefix);
  const payload = new Uint8Array(8 + addr.length);
  const view = new DataView(payload.buffer);
  view.setUint16(0, 8);
  view.setUint16(2, 4 + addr.length);
  view.setUint16(4, ip.family === 6 ? 2 : 1);
  payload[6] = prefix & 0xff;
  payload[7] = 0;
  payload.set(addr, 8);
  return payload;
}

function readEcs(msg) {
  if (!msg || !msg.opt) return null;
  const b = msg.bytes;
  for (const option of msg.opt.options) {
    if (option.code !== 8 || option.len < 4) continue;
    const family = (b[option.dataStart] << 8) | b[option.dataStart + 1];
    const prefix = b[option.dataStart + 2];
    if (family === 1 && option.len >= 8) {
      return { ip: { family: 4, bytes: b.slice(option.dataStart + 4, option.dataStart + 8) }, prefix };
    }
    if (family === 2 && option.len >= 20) {
      return { ip: { family: 6, bytes: b.slice(option.dataStart + 4, option.dataStart + 20) }, prefix };
    }
  }
  return null;
}

function withEcs(msg, payload) {
  const b = msg.bytes;
  const opt = msg.opt;

  if (opt) {
    const kept = [];
    for (const option of opt.options) {
      if (option.code !== 8) kept.push(b.subarray(option.start, option.end));
    }
    const rdata = concatBytes([...kept, payload]);
    const nameLen = opt.nameEnd - opt.rrStart;
    const head = new Uint8Array(nameLen + 10);
    head.set(b.subarray(opt.rrStart, opt.nameEnd), 0);
    const hv = new DataView(head.buffer);
    hv.setUint16(nameLen, TYPE_OPT);
    hv.setUint16(nameLen + 2, opt.cls);
    hv.setUint32(nameLen + 4, opt.ttl);   // TTL 承载扩展 rcode/version/flags
    hv.setUint16(nameLen + 8, rdata.length);
    return concatBytes([b.subarray(0, opt.rrStart), head, rdata, b.subarray(opt.rdEnd)]);
  }

  const rr = new Uint8Array(11 + payload.length);
  const rv = new DataView(rr.buffer);
  rr[0] = 0;
  rv.setUint16(1, TYPE_OPT);
  rv.setUint16(3, 1232);
  rv.setUint32(5, 0);
  rv.setUint16(9, payload.length);
  rr.set(payload, 11);

  const out = concatBytes([b, rr]);
  new DataView(out.buffer).setUint16(10, Math.min(0xffff, msg.arcount + 1));
  return out;
}

function parseEcsParam(text) {
  if (!text) return null;
  const [addr, prefixText] = String(text).split('/');
  const ip = parseIp(addr);
  if (!ip) return null;
  const max = ip.family === 6 ? 128 : 32;
  const prefix = prefixText === undefined ? max : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) return null;
  return { ip, prefix };
}

function getClientIp(request, cfg) {
  const direct = request.headers.get('cf-connecting-ip');
  if (direct) {
    const ip = parseIp(direct);
    if (ip) return ip;
  }
  if (cfg.trustXff) {
    const xff = request.headers.get('x-forwarded-for');
    if (xff) {
      const first = xff.split(',')[0];
      const ip = parseIp(first);
      if (ip) return ip;
    }
  }
  return null;
}

function pickEcs(request, url, cfg) {
  if (!cfg.ecs) return null;
  const fromParam = parseEcsParam(url.searchParams.get('ecs'));
  if (fromParam) return fromParam;
  const client = getClientIp(request, cfg);
  if (!client) return null;
  const prefix = client.family === 6 ? cfg.prefixV6 : cfg.prefixV4;
  if (prefix <= 0) return null;
  return { ip: client, prefix };
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type, accept',
  };
}

function wireHeaders() {
  return {
    'content-type': 'application/dns-message',
    'x-content-type-options': 'nosniff',
    ...corsHeaders(),
  };
}

function badRequest(message) {
  return new Response(message, {
    status: 400,
    headers: { 'content-type': 'text/plain; charset=utf-8', ...corsHeaders() },
  });
}

function servfail(msg) {
  const out = new Uint8Array(12);
  const view = new DataView(out.buffer);
  view.setUint16(0, msg ? msg.id : 0);
  view.setUint16(2, 0x8000 | 0x0080 | RCODE_SERVFAIL);
  return new Response(out, {
    status: 200,
    headers: { ...wireHeaders(), 'cache-control': 'no-store', 'x-doh': 'error' },
  });
}

function buildRecord(ip, ttl) {
  const rr = new Uint8Array(12 + ip.bytes.length);
  const view = new DataView(rr.buffer);
  rr[0] = 0xc0;
  rr[1] = 0x0c;   // 指向 question 的压缩指针
  view.setUint16(2, ip.family === 6 ? TYPE_AAAA : TYPE_A);
  view.setUint16(4, CLASS_IN);
  view.setUint32(6, ttl);
  view.setUint16(10, ip.bytes.length);
  rr.set(ip.bytes, 12);
  return rr;
}

// 类型不匹配返回 NODATA，不塞错误类型的记录
function wireAnswer(msg, decision, cfg) {
  const ttl = decision.source === 'block' ? cfg.blockTtl : cfg.answerTtl;
  const questionBytes = msg.bytes.subarray(12, msg.questionEnd);
  const answer = decision.ip ? buildRecord(decision.ip, ttl) : null;
  const out = new Uint8Array(12 + questionBytes.length + (answer ? answer.length : 0));
  const view = new DataView(out.buffer);
  view.setUint16(0, msg.id);
  view.setUint16(2, 0x8000 | (msg.flags & 0x0110) | 0x0080);
  view.setUint16(4, 1);
  view.setUint16(6, answer ? 1 : 0);
  view.setUint16(8, 0);
  view.setUint16(10, 0);
  out.set(questionBytes, 12);
  if (answer) out.set(answer, 12 + questionBytes.length);
  return new Response(out, {
    status: 200,
    headers: {
      ...wireHeaders(),
      'cache-control': `public, max-age=${ttl}`,
      'x-doh': decision.source,
    },
  });
}

function jsonAnswer(decision, cfg) {
  const ttl = decision.source === 'block' ? cfg.blockTtl : cfg.answerTtl;
  const body = {
    Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
    Question: [{ name: decision.name, type: decision.type }],
  };
  if (decision.ip) {
    body.Answer = [{
      name: decision.name,
      type: decision.ip.family === 6 ? TYPE_AAAA : TYPE_A,
      TTL: ttl,
      data: formatIp(decision.ip),
    }];
  }
  return Response.json(body, {
    headers: { 'cache-control': `public, max-age=${ttl}`, 'x-doh': decision.source, ...corsHeaders() },
  });
}

function normalizeName(name) {
  if (!name) return '';
  let s = String(name).trim().toLowerCase();
  if (s.endsWith('.')) s = s.slice(0, -1);
  return s;
}

function localDecision(env, cfg, question, rules) {
  if (!question) return null;
  const name = normalizeName(question.name);
  if (!name) return null;

  const custom = lookupCustom(name, getCustom(env));
  if (custom) {
    if (question.type === TYPE_A) {
      return { source: 'custom', name, type: question.type, ip: custom.v4.length ? custom.v4[0] : null };
    }
    if (question.type === TYPE_AAAA) {
      return { source: 'custom', name, type: question.type, ip: custom.v6.length ? custom.v6[0] : null };
    }
    return null;
  }

  if (decide(name, rules) === 'block') {
    let ip = null;
    if (question.type === TYPE_A) {
      const parsed = parseIp(cfg.blockIp);
      ip = parsed && parsed.family === 4 ? parsed : null;
    } else if (question.type === TYPE_AAAA) {
      const parsed = parseIp(cfg.blockIpV6);
      ip = parsed && parsed.family === 6 ? parsed : null;
    }
    return { source: 'block', name, type: question.type, ip };
  }
  return null;
}

async function upstreamFetch(primary, init, cfg) {
  const targets = [primary, ...cfg.fallbacks];
  let lastError = null;
  for (const target of targets) {
    try {
      const res = await fetch(target, { ...init, signal: AbortSignal.timeout(cfg.upstreamTimeout) });
      if (res.status < 500) return res;
      lastError = new Error(`upstream ${res.status}`);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error('no upstream available');
}

function decorate(res) {
  const headers = new Headers(res.headers);
  headers.set('access-control-allow-origin', '*');
  headers.set('x-content-type-options', 'nosniff');
  if (!headers.has('x-doh')) headers.set('x-doh', 'forward');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

async function forwardWire(msg, request, url, cfg) {
  const existing = readEcs(msg);
  let body = msg.bytes;
  if (!existing) {
    const ecs = pickEcs(request, url, cfg);
    if (ecs && ecs.prefix > 0) body = withEcs(msg, buildEcsPayload(ecs.ip, ecs.prefix));
  }
  try {
    const res = await upstreamFetch(cfg.dohUrl, {
      method: 'POST',
      headers: { accept: 'application/dns-message', 'content-type': 'application/dns-message' },
      body,
    }, cfg);
    return decorate(res);
  } catch (err) {
    console.warn('[doh] upstream POST failed:', err && err.message);
    return servfail(msg);
  }
}

async function forwardWireGet(msg, raw, request, url, cfg) {
  const existing = msg ? readEcs(msg) : null;
  let query = raw;
  if (msg && !existing) {
    const ecs = pickEcs(request, url, cfg);
    if (ecs && ecs.prefix > 0) query = toBase64Url(withEcs(msg, buildEcsPayload(ecs.ip, ecs.prefix)));
  }
  let target;
  try {
    target = new URL(cfg.dohUrl);
  } catch (err) {
    return servfail(msg);
  }
  target.searchParams.set('dns', query);
  try {
    const res = await upstreamFetch(target.toString(), {
      method: 'GET',
      headers: { accept: 'application/dns-message' },
    }, cfg);
    return decorate(res);
  } catch (err) {
    console.warn('[doh] upstream GET failed:', err && err.message);
    return servfail(msg);
  }
}

async function handleWirePost(request, url, env, cfg, rules) {
  let buffer;
  try {
    buffer = await request.arrayBuffer();
  } catch (err) {
    return badRequest('unreadable body');
  }
  if (buffer.byteLength < 12) return badRequest('message too short');
  if (buffer.byteLength > cfg.maxBody) {
    return new Response(null, { status: 413, headers: corsHeaders() });
  }

  const msg = walkMessage(buffer);
  if (!msg.ok) return badRequest('malformed dns message');

  if (msg.questions.length === 1 && (msg.flags & 0x7800) === 0) {
    const question = msg.questions[0];
    if (question.cls === CLASS_IN || question.cls === 255) {
      const decision = localDecision(env, cfg, question, rules);
      if (decision) return wireAnswer(msg, decision, cfg);
    }
  }
  return forwardWire(msg, request, url, cfg);
}

async function handleWireGet(request, url, env, cfg, rules) {
  const raw = url.searchParams.get('dns');
  if (!raw) return badRequest('missing dns parameter');
  if (raw.length > 8192) return new Response(null, { status: 414, headers: corsHeaders() });

  let bytes;
  try {
    bytes = fromBase64Url(raw);
  } catch (err) {
    return badRequest('bad base64url');
  }
  if (bytes.length < 12) return forwardWireGet(null, raw, request, url, cfg);

  const msg = walkMessage(exactBuffer(bytes));
  if (!msg.ok) return forwardWireGet(null, raw, request, url, cfg);

  if (msg.questions.length === 1 && (msg.flags & 0x7800) === 0) {
    const question = msg.questions[0];
    if (question.cls === CLASS_IN || question.cls === 255) {
      const decision = localDecision(env, cfg, question, rules);
      if (decision) return wireAnswer(msg, decision, cfg);
    }
  }
  return forwardWireGet(msg, raw, request, url, cfg);
}

async function handleJsonGet(request, url, env, cfg, rules) {
  const nameParam = url.searchParams.get('name');
  let type = Number(url.searchParams.get('type') || '1');
  if (!Number.isInteger(type) || type < 0 || type > 65535) type = TYPE_A;

  if (nameParam) {
    const question = { name: normalizeName(nameParam), type, cls: CLASS_IN };
    const decision = localDecision(env, cfg, question, rules);
    if (decision) return jsonAnswer(decision, cfg);
  }

  let target;
  try {
    target = new URL(cfg.dohUrl);
  } catch (err) {
    return Response.json({ Status: RCODE_SERVFAIL }, { headers: corsHeaders() });
  }
  for (const [key, value] of url.searchParams) {
    if (key !== 'ecs') target.searchParams.set(key, value);
  }
  const clientEcs = parseEcsParam(url.searchParams.get('ecs'));
  const ecs = clientEcs || pickEcs(request, url, cfg);
  if (ecs && ecs.prefix > 0) {
    // 本地生成的先掩码，避免泄漏完整 IP
    const addr = clientEcs ? clientEcs.ip : { family: ecs.ip.family, bytes: maskAddress(ecs.ip.bytes, ecs.prefix) };
    target.searchParams.set('ecs', `${formatIp(addr)}/${ecs.prefix}`);
  } else {
    target.searchParams.delete('ecs');
  }

  try {
    const res = await upstreamFetch(target.toString(), {
      method: 'GET',
      headers: { accept: 'application/dns-json' },
    }, cfg);
    return decorate(res);
  } catch (err) {
    console.warn('[doh] upstream JSON failed:', err && err.message);
    return Response.json({ Status: RCODE_SERVFAIL }, { headers: corsHeaders() });
  }
}

const FALLBACK_HTML = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">'
  + '<title>DNS over HTTPS</title></head><body><h1>DNS over HTTPS</h1>'
  + '<p>当前路径：<code>/dns-query</code>。未检测到 ASSETS 绑定，静态页面未部署。</p></body></html>';

async function serveStatic(env, request) {
  const assets = env && env.ASSETS;
  if (!assets || typeof assets.fetch !== 'function') {
    return new Response(FALLBACK_HTML, {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    });
  }

  let res;
  try {
    res = await assets.fetch(request);
  } catch (err) {
    console.warn('[static] asset fetch failed:', err && err.message);
    return new Response('asset unavailable', { status: 502 });
  }
  if (res.status !== 404) return res;

  const url = new URL(request.url);
  const accept = (request.headers.get('accept') || '').toLowerCase();
  const isNavigation = request.method === 'GET'
    && accept.includes('text/html')
    && !/\.[a-z0-9]{1,8}$/i.test(url.pathname);
  if (!isNavigation) return res;

  for (const candidate of ['/index.html', '/']) {
    try {
      const index = await assets.fetch(new Request(new URL(candidate, url).toString(), {
        method: 'GET',
        headers: { accept: 'text/html' },
      }));
      if (index && index.status === 200) return index;
    } catch (err) {
      console.warn('[static] index fallback failed:', err && err.message);
    }
  }
  return res;
}
