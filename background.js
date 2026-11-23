// WebGuard Island - Background Service Worker

const AD_AND_TRACKER_PATTERNS = [
  'doubleclick.net',
  'googlesyndication.com',
  'googleadservices.com',
  'adnxs.com',
  'taboola.com',
  'outbrain.com',
  'popads.net',
  'popcash.net',
  'propellerads.com',
  'exoclick.com',
  'juicyads.com',
  'mgid.com',
  'criteo.com',
  'pubmatic.com',
  'rubiconproject.com',
  'openx.net',
  'casalemedia.com',
  'adservice.google.',
  'adsrvr.org',
  'adform.net',
  'scorecardresearch.com',
  'amazon-adsystem.com',
  'media.net',
  'revcontent.com',
  'adsterra.com',
  'trafficjunky.net',
  'clickadu.com',
  'hilltopads.net',
  'onclasrv.com'
];

// 三類外部公開清單來源（手動更新）
const THREAT_LIST_SOURCES = [
  {
    id: 'phishing-army',
    name: 'Phishing Army Blocklist',
    category: '防詐騙網域清單',
    type: 'domain',
    url: 'https://phishing.army/download/phishing_army_blocklist.txt',
    maxItems: 12000
  },
  {
    id: 'openphish',
    name: 'OpenPhish Feed',
    category: '防詐騙網域清單',
    type: 'url_to_domain',
    url: 'https://openphish.com/feed.txt',
    maxItems: 2000
  },
  {
    id: 'feodo-ip',
    name: 'abuse.ch Feodo Tracker (C2 IP)',
    category: 'IP / 資安威脅黑名單',
    type: 'ip',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    maxItems: 2000
  },
  {
    id: 'blocklist-de',
    name: 'Blocklist.de (攻擊與惡意 IP)',
    category: 'IP / 資安威脅黑名單',
    type: 'ip',
    url: 'https://lists.blocklist.de/lists/all.txt',
    maxItems: 5000
  },
  {
    id: 'peter-lowe',
    name: "Peter Lowe's Ad & Tracking List",
    category: '廣告 / 追蹤過濾清單',
    type: 'hosts',
    url: 'https://pgl.yoyo.org/as/serverlist.php?hostformat=hosts&mimetype=plaintext&useip=0.0.0.0',
    maxItems: 5000
  }
];

const GEOIP_HOSTS = new Set(['api.country.is', 'ipwho.is']);
const LIST_HOSTS = new Set([
  'phishing.army',
  'openphish.com',
  'feodotracker.abuse.ch',
  'lists.blocklist.de',
  'pgl.yoyo.org'
]);
const DANGEROUS_EXT_RE = /\.(exe|msi|bat|cmd|scr|vbs|ps1|pif|com|hta|jar|apk)(\?|$)/i;

// In-memory state
const tabStates = new Map();
let geoipCache = {}; // ip -> { country: 'CN', ts: number }
let cnIpSet = {};    // ip -> true (permanent local memory of Mainland China IPs)
let blockedDomains = [];
let whitelistedDomains = [];
let threatListsData = {}; // id -> { items: [], updatedAt: number|null, error: string|null }

// Fast lookup maps built from threatListsData
let threatDomainMap = new Map(); // domain -> { category, listName }
let threatIpMap = new Map();     // ip -> { category, listName }

const pendingLookups = new Map();
const lookupQueue = [];
let activeLookups = 0;
const MAX_CONCURRENT_LOOKUPS = 3;

const notifyTimers = new Map();

function rebuildThreatMaps() {
  threatDomainMap = new Map();
  threatIpMap = new Map();
  for (const src of THREAT_LIST_SOURCES) {
    const entry = threatListsData[src.id];
    if (!entry || !Array.isArray(entry.items)) continue;
    for (const item of entry.items) {
      if (src.type === 'ip' || /^\d{1,3}(\.\d{1,3}){3}$/.test(item)) {
        if (!threatIpMap.has(item)) {
          threatIpMap.set(item, { category: src.category, listName: src.name });
        }
      } else {
        if (!threatDomainMap.has(item)) {
          threatDomainMap.set(item, { category: src.category, listName: src.name });
        }
      }
    }
  }
}

async function initStorage() {
  const data = await chrome.storage.local.get([
    'geoipCache',
    'cnIpSet',
    'blockedDomains',
    'whitelistedDomains',
    'threatListsData'
  ]);
  geoipCache = data.geoipCache || {};
  cnIpSet = data.cnIpSet || {};
  blockedDomains = data.blockedDomains || [];
  whitelistedDomains = data.whitelistedDomains || [];
  threatListsData = data.threatListsData || {};
  rebuildThreatMaps();
  await syncDynamicBlockRules();
}

const storageReady = initStorage();

function getDomain(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isPrivateOrLocalIp(ip) {
  if (!ip) return true;
  if (ip === '::1' || ip === '0.0.0.0') return true;
  if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) {
    return true;
  }
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  const lower = ip.toLowerCase();
  if (lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:')) {
    return true;
  }
  return false;
}

function isAdDomain(domain) {
  if (!domain) return false;
  for (const pat of AD_AND_TRACKER_PATTERNS) {
    if (domain.includes(pat)) return true;
  }
  if (/^(ad|ads|adserver|track|tracker|pop|popup)\d*\./i.test(domain)) return true;
  return false;
}

function matchThreatDomain(domain) {
  if (!domain) return null;
  if (threatDomainMap.has(domain)) return threatDomainMap.get(domain);
  const parts = domain.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join('.');
    if (threatDomainMap.has(parent)) return threatDomainMap.get(parent);
  }
  return null;
}

function createEmptyTabState(url = '') {
  return {
    url,
    mainDomain: getDomain(url),
    redirects: [],
    connections: {},
    requestCount: 0,
    totalBytes: 0,
    keyloggers: [],
    suspiciousDownloads: [],
    threatHits: [], // 命中三大黑名單並直接封鎖的紀錄
    updatedAt: Date.now()
  };
}

function getOrCreateTabState(tabId, url = '') {
  if (!tabStates.has(tabId)) {
    tabStates.set(tabId, createEmptyTabState(url));
  }
  const st = tabStates.get(tabId);
  if (url && !st.mainDomain) {
    st.url = url;
    st.mainDomain = getDomain(url);
  }
  return st;
}

function scheduleTabNotify(tabId) {
  if (tabId < 0) return;
  if (notifyTimers.has(tabId)) return;
  const timer = setTimeout(() => {
    notifyTimers.delete(tabId);
    const payload = buildTabSummary(tabId);
    if (!payload) return;
    chrome.tabs.sendMessage(tabId, { type: 'WEBGUARD_STATE_UPDATE', payload }).catch(() => {});
  }, 350);
  notifyTimers.set(tabId, timer);
}

function computeStatus(st) {
  const hasKeylogger = st.keyloggers.length > 0;
  const hasThreatHit = st.threatHits.length > 0;
  const connList = Object.values(st.connections);
  const hasCN = connList.some((c) => c.isCN);
  const hasAd = connList.some((c) => c.isAd);
  const hasJump = st.redirects.some((r) => {
    const d1 = getDomain(r.from);
    const d2 = getDomain(r.to);
    return d1 && d2 && d1 !== d2;
  }) || st.redirects.length >= 2;
  const hasSuspiciousDownload = st.suspiciousDownloads.length > 0;

  if (hasKeylogger) {
    return { level: 'red', label: '偵測側錄', reason: '發現可疑第三方鍵盤/輸入監聽' };
  }
  if (hasThreatHit) {
    return {
      level: 'blackgold',
      label: `黑金封鎖 (${st.threatHits.length})`,
      reason: '命中防詐騙／威脅IP／廣告追蹤黑名單，已直接封鎖'
    };
  }
  if (hasCN) {
    return { level: 'black', label: '含大陸 IP', reason: '偵測到連線至中國大陸 IP 節點' };
  }
  if (hasAd || hasJump || hasSuspiciousDownload) {
    const reasons = [];
    if (hasAd) reasons.push('廣告/追蹤');
    if (hasJump) reasons.push('跨站跳板');
    if (hasSuspiciousDownload) reasons.push('可疑下載');
    return { level: 'orange', label: reasons.join(' · '), reason: reasons.join('、') };
  }
  return { level: 'green', label: '安全網站', reason: '未發現側錄、黑名單、大陸 IP 或異常跳板' };
}

function buildTabSummary(tabId) {
  const st = tabStates.get(tabId);
  if (!st) return null;
  const status = computeStatus(st);
  const connections = Object.values(st.connections).sort((a, b) => {
    if (a.isCN !== b.isCN) return a.isCN ? -1 : 1;
    if (a.isAd !== b.isAd) return a.isAd ? -1 : 1;
    return b.count - a.count;
  });
  const thirdPartyCount = connections.filter((c) => c.domain && c.domain !== st.mainDomain).length;
  const cnCount = connections.filter((c) => c.isCN).length;

  return {
    url: st.url,
    mainDomain: st.mainDomain,
    isHttps: st.url.startsWith('https://'),
    status,
    requestCount: st.requestCount,
    totalBytes: st.totalBytes,
    thirdPartyCount,
    cnCount,
    cnCacheCount: Object.keys(cnIpSet).length,
    geoipCacheCount: Object.keys(geoipCache).length,
    threatListTotal: threatDomainMap.size + threatIpMap.size,
    redirects: st.redirects.slice(-15),
    keyloggers: st.keyloggers.slice(-15),
    suspiciousDownloads: st.suspiciousDownloads.slice(-10),
    threatHits: st.threatHits.slice(-20),
    connections: connections.slice(0, 60),
    isWhitelisted: whitelistedDomains.includes(st.mainDomain)
  };
}

// GeoIP Lookup with permanent CN IP cache
let saveCacheTimer = null;
function scheduleCacheSave() {
  if (saveCacheTimer) return;
  saveCacheTimer = setTimeout(() => {
    saveCacheTimer = null;
    const keys = Object.keys(geoipCache);
    if (keys.length > 5000) {
      keys.sort((a, b) => (geoipCache[a].ts || 0) - (geoipCache[b].ts || 0));
      for (let i = 0; i < keys.length - 5000; i++) {
        delete geoipCache[keys[i]];
      }
    }
    chrome.storage.local.set({ geoipCache, cnIpSet });
  }, 1500);
}

async function fetchGeoIpFromNetwork(ip) {
  try {
    const res = await fetch(`https://api.country.is/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(4500)
    });
    if (res.ok) {
      const json = await res.json();
      if (json && json.country) return String(json.country).toUpperCase();
    }
  } catch {}
  try {
    const res2 = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(4500)
    });
    if (res2.ok) {
      const json2 = await res2.json();
      if (json2 && json2.success !== false && json2.country_code) {
        return String(json2.country_code).toUpperCase();
      }
    }
  } catch {}
  return null;
}

function processLookupQueue() {
  while (activeLookups < MAX_CONCURRENT_LOOKUPS && lookupQueue.length > 0) {
    const item = lookupQueue.shift();
    activeLookups++;
    fetchGeoIpFromNetwork(item.ip)
      .then((countryCode) => {
        if (countryCode) {
          geoipCache[item.ip] = { country: countryCode, ts: Date.now() };
          if (countryCode === 'CN') cnIpSet[item.ip] = true;
          scheduleCacheSave();
        }
        item.resolve(countryCode);
      })
      .catch(() => item.resolve(null))
      .finally(() => {
        activeLookups--;
        pendingLookups.delete(item.ip);
        processLookupQueue();
      });
  }
}

async function lookupIpCountry(ip) {
  await storageReady;
  if (isPrivateOrLocalIp(ip)) return 'LOCAL';
  if (cnIpSet[ip]) return 'CN';
  if (geoipCache[ip] && geoipCache[ip].country) return geoipCache[ip].country;
  if (pendingLookups.has(ip)) return pendingLookups.get(ip);

  const promise = new Promise((resolve) => {
    lookupQueue.push({ ip, resolve });
    processLookupQueue();
  });
  pendingLookups.set(ip, promise);
  return promise;
}

// Parse & Update external threat lists manually
function parseListText(text, src) {
  const lines = text.split(/\r?\n/);
  const result = [];
  const seen = new Set();

  for (let raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('!') || line.startsWith(';')) continue;

    let item = '';
    if (src.type === 'hosts') {
      const parts = line.split(/\s+/);
      const host = parts.length >= 2 ? parts[1] : parts[0];
      if (host && host !== 'localhost' && host !== '0.0.0.0' && host !== '127.0.0.1') {
        item = host.toLowerCase();
      }
    } else if (src.type === 'url_to_domain') {
      try {
        item = new URL(line).hostname.toLowerCase();
      } catch {
        // ignore invalid url
      }
    } else if (src.type === 'ip') {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(line)) {
        item = line;
      }
    } else {
      item = line.toLowerCase().replace(/^\*\./, '');
    }

    if (item && !seen.has(item)) {
      seen.add(item);
      result.push(item);
      if (result.length >= (src.maxItems || 10000)) break;
    }
  }
  return result;
}

async function updateSingleList(id) {
  const src = THREAT_LIST_SOURCES.find((s) => s.id === id);
  if (!src) return { ok: false, error: '找不到清單' };
  try {
    const res = await fetch(src.url, { signal: AbortSignal.timeout(15000), cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const items = parseListText(text, src);
    threatListsData[src.id] = {
      items,
      updatedAt: Date.now(),
      error: null
    };
    return { ok: true, count: items.length };
  } catch (err) {
    threatListsData[src.id] = {
      items: threatListsData[src.id]?.items || [],
      updatedAt: threatListsData[src.id]?.updatedAt || null,
      error: err.message || '下載失敗'
    };
    return { ok: false, error: err.message };
  }
}

function getListsMetadata() {
  return THREAT_LIST_SOURCES.map((src) => {
    const entry = threatListsData[src.id];
    return {
      id: src.id,
      name: src.name,
      category: src.category,
      url: src.url,
      count: entry?.items?.length || 0,
      updatedAt: entry?.updatedAt || null,
      error: entry?.error || null
    };
  });
}

// Dynamic declarativeNetRequest blocking (User blocked + External 3-category lists)
const ALL_RESOURCE_TYPES = [
  'main_frame',
  'sub_frame',
  'stylesheet',
  'script',
  'image',
  'font',
  'object',
  'xmlhttprequest',
  'ping',
  'media',
  'websocket',
  'other'
];

async function syncDynamicBlockRules() {
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing.map((r) => r.id);

    const addRules = [];
    let ruleId = 1;

    // 1. User custom blocked domains (priority 2)
    for (const domain of blockedDomains) {
      if (ruleId > 1000) break;
      addRules.push({
        id: ruleId++,
        priority: 2,
        action: { type: 'block' },
        condition: {
          urlFilter: `||${domain}^`,
          resourceTypes: ALL_RESOURCE_TYPES
        }
      });
    }

    // 2. External threat lists (direct block)
    const maxRulesLimit = Math.min(
      chrome.declarativeNetRequest.MAX_NUMBER_OF_DYNAMIC_AND_SESSION_RULES || 25000,
      25000
    );

    const combinedTargets = new Set();
    for (const domain of threatDomainMap.keys()) {
      if (!LIST_HOSTS.has(domain)) combinedTargets.add(domain);
    }
    for (const ip of threatIpMap.keys()) {
      combinedTargets.add(ip);
    }

    for (const target of combinedTargets) {
      if (ruleId >= maxRulesLimit) break;
      addRules.push({
        id: ruleId++,
        priority: 1,
        action: { type: 'block' },
        condition: {
          urlFilter: `||${target}^`,
          resourceTypes: ALL_RESOURCE_TYPES
        }
      });
    }

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules
    });
  } catch (err) {
    console.warn('Failed to sync full DNR rules, retrying with 4500 cap:', err);
    try {
      const existing = await chrome.declarativeNetRequest.getDynamicRules();
      const removeRuleIds = existing.map((r) => r.id);
      const fallbackRules = [];
      let id = 1;
      for (const domain of blockedDomains) {
        fallbackRules.push({
          id: id++,
          priority: 2,
          action: { type: 'block' },
          condition: { urlFilter: `||${domain}^`, resourceTypes: ALL_RESOURCE_TYPES }
        });
      }
      for (const target of threatDomainMap.keys()) {
        if (id > 4500) break;
        fallbackRules.push({
          id: id++,
          priority: 1,
          action: { type: 'block' },
          condition: { urlFilter: `||${target}^`, resourceTypes: ALL_RESOURCE_TYPES }
        });
      }
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: fallbackRules });
    } catch (e2) {
      console.warn('DNR fallback failed:', e2);
    }
  }
}

// Reset tab state on main frame navigation start
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) return;
  if (!details.url.startsWith('http')) return;
  tabStates.set(details.tabId, createEmptyTabState(details.url));
});

// Check incoming requests against the 3 external lists (fires even if DNR blocks it!)
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const domain = getDomain(details.url);
    if (!domain || GEOIP_HOSTS.has(domain) || LIST_HOSTS.has(domain)) return;

    const hit = matchThreatDomain(domain) || threatIpMap.get(domain);
    if (hit) {
      const st = getOrCreateTabState(details.tabId, details.type === 'main_frame' ? details.url : '');
      const exists = st.threatHits.some((h) => h.target === domain);
      if (!exists) {
        st.threatHits.push({
          target: domain,
          category: hit.category,
          listName: hit.listName,
          blocked: true,
          ts: Date.now()
        });
        scheduleTabNotify(details.tabId);
      }
    }
  },
  { urls: ['<all_urls>'] }
);

// Track redirects (跳板)
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (details.type !== 'main_frame' && details.type !== 'sub_frame') return;
    const st = getOrCreateTabState(details.tabId, details.url);
    st.redirects.push({
      from: details.url,
      to: details.redirectUrl,
      statusCode: details.statusCode,
      ts: Date.now()
    });
    if (details.type === 'main_frame' && details.redirectUrl) {
      st.url = details.redirectUrl;
      st.mainDomain = getDomain(details.redirectUrl);
    }
    scheduleTabNotify(details.tabId);
  },
  { urls: ['<all_urls>'] }
);

// Track completed requests, size, IP & GeoIP
chrome.webRequest.onCompleted.addListener(
  async (details) => {
    if (details.tabId < 0) return;
    const domain = getDomain(details.url);
    if (!domain || GEOIP_HOSTS.has(domain) || LIST_HOSTS.has(domain)) return;

    const st = getOrCreateTabState(details.tabId, details.type === 'main_frame' ? details.url : '');
    if (details.type === 'main_frame') {
      st.url = details.url;
      st.mainDomain = domain;
    }

    st.requestCount += 1;

    let bytes = 0;
    if (details.responseHeaders) {
      const cl = details.responseHeaders.find((h) => h.name.toLowerCase() === 'content-length');
      if (cl && cl.value) bytes = parseInt(cl.value, 10) || 0;
    }
    st.totalBytes += bytes;

    // Also check resolved IP against threatIpMap
    if (details.ip && threatIpMap.has(details.ip)) {
      const hit = threatIpMap.get(details.ip);
      const exists = st.threatHits.some((h) => h.target === details.ip);
      if (!exists) {
        st.threatHits.push({
          target: `${domain} (${details.ip})`,
          category: hit.category,
          listName: hit.listName,
          blocked: true,
          ts: Date.now()
        });
      }
    }

    if (!st.connections[domain]) {
      st.connections[domain] = {
        domain,
        ip: details.ip || '',
        countryCode: '',
        isCN: false,
        isAd: isAdDomain(domain),
        count: 0,
        bytes: 0,
        types: []
      };
    }

    const conn = st.connections[domain];
    conn.count += 1;
    conn.bytes += bytes;
    if (details.ip) conn.ip = details.ip;
    if (!conn.types.includes(details.type)) conn.types.push(details.type);

    scheduleTabNotify(details.tabId);

    if (details.ip && !conn.countryCode) {
      const countryCode = await lookupIpCountry(details.ip);
      if (countryCode) {
        conn.countryCode = countryCode;
        conn.isCN = countryCode === 'CN';
        scheduleTabNotify(details.tabId);
      }
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// Track suspicious downloads
chrome.downloads.onCreated.addListener((item) => {
  const nameOrUrl = item.filename || item.url || '';
  if (DANGEROUS_EXT_RE.test(nameOrUrl)) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        const st = getOrCreateTabState(tabs[0].id, tabs[0].url);
        st.suspiciousDownloads.push({
          filename: item.filename || item.url.split('/').pop() || 'unknown',
          url: item.url,
          ts: Date.now()
        });
        scheduleTabNotify(tabs[0].id);
      }
    });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
  if (notifyTimers.has(tabId)) {
    clearTimeout(notifyTimers.get(tabId));
    notifyTimers.delete(tabId);
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return;

  if (msg.type === 'WEBGUARD_GET_STATE') {
    const tabId = msg.tabId ?? sender.tab?.id;
    storageReady.then(() => {
      if (tabId !== undefined) {
        getOrCreateTabState(tabId, sender.tab?.url || '');
        sendResponse({ ok: true, payload: buildTabSummary(tabId) });
      } else {
        sendResponse({ ok: false });
      }
    });
    return true;
  }

  if (msg.type === 'WEBGUARD_KEYLOGGER_ALERT' && sender.tab?.id >= 0) {
    const st = getOrCreateTabState(sender.tab.id, sender.tab.url);
    const exists = st.keyloggers.some(
      (k) => k.scriptUrl === msg.scriptUrl && k.eventType === msg.eventType
    );
    if (!exists) {
      st.keyloggers.push({
        eventType: msg.eventType,
        targetDesc: msg.targetDesc,
        scriptUrl: msg.scriptUrl,
        ts: Date.now()
      });
      scheduleTabNotify(sender.tab.id);
    }
    return false;
  }

  if (msg.type === 'WEBGUARD_OPEN_LISTS_PAGE') {
    chrome.tabs.create({ url: chrome.runtime.getURL('lists.html') });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'WEBGUARD_GET_LISTS_INFO') {
    storageReady.then(() => {
      sendResponse({
        ok: true,
        lists: getListsMetadata(),
        totalDomains: threatDomainMap.size,
        totalIps: threatIpMap.size,
        blockedDomains
      });
    });
    return true;
  }

  if (msg.type === 'WEBGUARD_UPDATE_LIST') {
    storageReady.then(async () => {
      if (msg.id === 'all') {
        for (const src of THREAT_LIST_SOURCES) {
          await updateSingleList(src.id);
        }
      } else {
        await updateSingleList(msg.id);
      }
      await chrome.storage.local.set({ threatListsData });
      rebuildThreatMaps();
      await syncDynamicBlockRules();
      sendResponse({
        ok: true,
        lists: getListsMetadata(),
        totalDomains: threatDomainMap.size,
        totalIps: threatIpMap.size
      });
    });
    return true;
  }

  if (msg.type === 'WEBGUARD_SEARCH_LIST') {
    const q = (msg.query || '').toLowerCase().trim();
    storageReady.then(() => {
      if (!q) {
        sendResponse({ ok: true, matches: [] });
        return;
      }
      const matches = [];
      for (const [domain, info] of threatDomainMap.entries()) {
        if (domain.includes(q)) {
          matches.push({ target: domain, ...info });
          if (matches.length >= 50) break;
        }
      }
      if (matches.length < 50) {
        for (const [ip, info] of threatIpMap.entries()) {
          if (ip.includes(q)) {
            matches.push({ target: ip, ...info });
            if (matches.length >= 50) break;
          }
        }
      }
      sendResponse({ ok: true, matches });
    });
    return true;
  }

  if (msg.type === 'WEBGUARD_BLOCK_DOMAIN') {
    const domain = (msg.domain || '').toLowerCase().trim();
    if (!domain) {
      sendResponse({ ok: false });
      return false;
    }
    storageReady.then(async () => {
      if (!blockedDomains.includes(domain)) {
        blockedDomains.push(domain);
        await chrome.storage.local.set({ blockedDomains });
        await syncDynamicBlockRules();
      }
      sendResponse({ ok: true, blockedDomains });
    });
    return true;
  }

  if (msg.type === 'WEBGUARD_UNBLOCK_DOMAIN') {
    const domain = (msg.domain || '').toLowerCase().trim();
    storageReady.then(async () => {
      blockedDomains = blockedDomains.filter((d) => d !== domain);
      await chrome.storage.local.set({ blockedDomains });
      await syncDynamicBlockRules();
      sendResponse({ ok: true, blockedDomains });
    });
    return true;
  }

  if (msg.type === 'WEBGUARD_TOGGLE_WHITELIST') {
    const domain = (msg.domain || '').toLowerCase().trim();
    storageReady.then(async () => {
      if (whitelistedDomains.includes(domain)) {
        whitelistedDomains = whitelistedDomains.filter((d) => d !== domain);
      } else if (domain) {
        whitelistedDomains.push(domain);
      }
      await chrome.storage.local.set({ whitelistedDomains });
      if (sender.tab?.id >= 0) scheduleTabNotify(sender.tab.id);
      sendResponse({ ok: true, whitelistedDomains });
    });
    return true;
  }

  if (msg.type === 'WEBGUARD_GET_SETTINGS') {
    storageReady.then(() => {
      sendResponse({
        ok: true,
        blockedDomains,
        whitelistedDomains,
        cnCacheCount: Object.keys(cnIpSet).length,
        geoipCacheCount: Object.keys(geoipCache).length,
        threatListTotal: threatDomainMap.size + threatIpMap.size
      });
    });
    return true;
  }

  if (msg.type === 'WEBGUARD_CLEAR_GEOIP_CACHE') {
    storageReady.then(async () => {
      geoipCache = {};
      cnIpSet = {};
      await chrome.storage.local.set({ geoipCache, cnIpSet });
      sendResponse({ ok: true });
    });
    return true;
  }
});
