// WebGuard Island - Main World Hook for Keylogger / Skimmer Detection
(function () {
  if (window.__webguardHooked) return;
  window.__webguardHooked = true;

  const SENSITIVE_EVENTS = new Set(['keydown', 'keypress', 'keyup', 'input', 'paste', 'copy']);
  const reportedKeys = new Set();

  // 同集團官方 CDN 對應表：避免主站載入自家 CDN 腳本時誤報側錄
  const FIRST_PARTY_CDN_GROUPS = [
    ['facebook.com', 'fbcdn.net', 'fbsbx.com', 'instagram.com', 'cdninstagram.com', 'threads.net', 'messenger.com'],
    ['google.com', 'youtube.com', 'youtu.be', 'gstatic.com', 'googleusercontent.com', 'ytimg.com', 'ggpht.com', 'googleapis.com'],
    ['x.com', 'twitter.com', 'twimg.com'],
    ['github.com', 'githubassets.com', 'githubusercontent.com'],
    ['microsoft.com', 'live.com', 'office.com', 'office.net', 'msecnd.net', 'msftauth.net', 'sharepoint.com'],
    ['discord.com', 'discordapp.com', 'discordcdn.com'],
    ['twitch.tv', 'ttvnw.net', 'jtvnw.net'],
    ['yahoo.com', 'yimg.com'],
    ['shopee.tw', 'shopee.com', 'shopeemobile.com', 'susercontent.com'],
    ['pchome.com.tw', 'ecimg.tw'],
    ['momoshop.com.tw', 'momoshop.com', 'momo.com.tw']
  ];

  // 常見合法行銷追蹤 / 客服 / 驗證套件：一般全域互動監聽不視為高危側錄（仍會由網路層判斷廣告/封鎖），
  // 但若直接監聽密碼或信用卡欄位則一律照樣亮紅燈。
  const KNOWN_ANALYTICS_OR_WIDGET_HOSTS = [
    'googletagmanager.com',
    'google-analytics.com',
    'analytics.google.com',
    'connect.facebook.net',
    'scdn.line-apps.com',
    'line-scdn.net',
    'criteo.com',
    'appier.net',
    'hotjar.com',
    'clarity.ms',
    'bat.bing.com',
    'analytics.tiktok.com',
    'doubleclick.net',
    'googlesyndication.com',
    'googleadservices.com',
    'intercom.io',
    'zendesk.com',
    'zdassets.com',
    'tawk.to',
    'crisp.chat',
    'recaptcha.net',
    'hcaptcha.com',
    'challenges.cloudflare.com'
  ];

  function isKnownAnalyticsOrWidget(scriptUrl) {
    try {
      const host = new URL(scriptUrl).hostname.toLowerCase();
      return KNOWN_ANALYTICS_OR_WIDGET_HOSTS.some((d) => hostMatchesDomain(host, d));
    } catch {
      return false;
    }
  }

  function hostMatchesDomain(host, domain) {
    return host === domain || host.endsWith('.' + domain);
  }

  function isSameCompanyGroup(pageHost, scriptHost) {
    for (const group of FIRST_PARTY_CDN_GROUPS) {
      const pageInGroup = group.some((d) => hostMatchesDomain(pageHost, d));
      const scriptInGroup = group.some((d) => hostMatchesDomain(scriptHost, d));
      if (pageInGroup && scriptInGroup) return true;
    }
    return false;
  }

  function extractCallerUrl() {
    try {
      const stack = new Error().stack || '';
      const lines = stack.split('\n');
      for (let i = 2; i < lines.length; i++) {
        const line = lines[i];
        const match = line.match(/(https?:\/\/[^\s):]+|blob:[^\s):]+|data:[^\s):]+)/);
        if (match && match[1]) {
          return match[1];
        }
      }
      if (stack.includes('eval') || stack.includes('<anonymous>')) {
        return 'eval/inline-anonymous';
      }
    } catch {
      // ignore
    }
    return '';
  }

  function isThirdPartyScript(scriptUrl) {
    if (!scriptUrl) return false;
    if (scriptUrl === 'eval/inline-anonymous' || scriptUrl.startsWith('blob:') || scriptUrl.startsWith('data:')) {
      return true;
    }
    try {
      const scriptHost = new URL(scriptUrl).hostname.toLowerCase();
      const pageHost = location.hostname.toLowerCase();
      if (!scriptHost || !pageHost) return false;
      if (scriptHost === pageHost || scriptHost.endsWith('.' + pageHost) || pageHost.endsWith('.' + scriptHost)) {
        return false;
      }
      if (isSameCompanyGroup(pageHost, scriptHost)) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  function describeTarget(target) {
    if (target === window) return 'window';
    if (target === document) return 'document';
    if (target === document.documentElement) return 'html';
    if (target === document.body) return 'body';
    if (target && target.tagName) {
      const tag = target.tagName.toLowerCase();
      const type = target.type ? `[type=${target.type}]` : '';
      return `${tag}${type}`;
    }
    return 'unknown';
  }

  function isSensitiveFieldTarget(target) {
    if (target && target.tagName === 'INPUT') {
      const t = (target.type || '').toLowerCase();
      const ac = (target.autocomplete || '').toLowerCase();
      if (t === 'password' || ac.includes('cc-') || ac.includes('card')) {
        return true;
      }
    }
    return false;
  }

  function isGlobalTarget(target) {
    return (
      target === window ||
      target === document ||
      target === document.documentElement ||
      target === document.body
    );
  }

  const origAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    // 避免網頁自身觸發 Permissions-Policy unload 違規時被 Chrome 記成外掛錯誤
    if (
      typeof type === 'string' &&
      type.toLowerCase() === 'unload' &&
      document.featurePolicy &&
      typeof document.featurePolicy.allowsFeature === 'function' &&
      !document.featurePolicy.allowsFeature('unload')
    ) {
      return;
    }
    try {
      if (typeof type === 'string' && SENSITIVE_EVENTS.has(type.toLowerCase())) {
        const sensitiveField = isSensitiveFieldTarget(this);
        const globalTarget = isGlobalTarget(this);
        if (sensitiveField || globalTarget) {
          const scriptUrl = extractCallerUrl();
          if (isThirdPartyScript(scriptUrl)) {
            // 若非密碼/卡號欄位，且為已知行銷追蹤/客服/驗證套件，則不誤報高危紅燈
            if (!sensitiveField && isKnownAnalyticsOrWidget(scriptUrl)) {
              return origAddEventListener.call(this, type, listener, options);
            }
            const targetDesc = describeTarget(this);
            const dedupKey = `${type}|${targetDesc}|${scriptUrl}`;
            if (!reportedKeys.has(dedupKey)) {
              reportedKeys.add(dedupKey);
              window.postMessage(
                {
                  source: 'WEBGUARD_PAGE_HOOK',
                  type: 'KEYLOGGER_ALERT',
                  eventType: type.toLowerCase(),
                  targetDesc,
                  scriptUrl
                },
                '*'
              );
            }
          }
        }
      }
    } catch {
      // Never break host page
    }
    return origAddEventListener.call(this, type, listener, options);
  };
})();
