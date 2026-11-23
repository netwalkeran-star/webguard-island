// WebGuard Island - Content Script (Shadow DOM Dynamic Island + Safe Close)
(function () {
  if (window.top !== window.self) return;
  if (window.__webguardContentLoaded) return;
  window.__webguardContentLoaded = true;

  let currentState = null;
  let isExpanded = false;
  let isMinimized = false;
  let isHovering = false;
  let pageLoaded = document.readyState === 'complete';
  let shrinkTimer = null;
  let activeTab = 'threats'; // 'threats' | 'connections'
  let safeCloseMode = false;
  let highlightedEl = null;
  let origOutline = '';
  let hostEl = null;
  let shadow = null;

  // Forward keylogger alerts from MAIN world hook to background
  window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data) return;
    if (event.data.source === 'WEBGUARD_PAGE_HOOK' && event.data.type === 'KEYLOGGER_ALERT') {
      chrome.runtime.sendMessage({
        type: 'WEBGUARD_KEYLOGGER_ALERT',
        eventType: event.data.eventType,
        targetDesc: event.data.targetDesc,
        scriptUrl: event.data.scriptUrl
      }).catch(() => {});
    }
  });

  // Listen for state updates from background
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'WEBGUARD_STATE_UPDATE' && msg.payload) {
      currentState = msg.payload;
      renderUI();
    }
  });

  function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 KB';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function getPerfPageBytes() {
    try {
      const resources = performance.getEntriesByType('resource') || [];
      let sum = 0;
      for (const r of resources) {
        sum += r.transferSize || r.encodedBodySize || 0;
      }
      const nav = performance.getEntriesByType('navigation') || [];
      if (nav[0]) {
        sum += nav[0].transferSize || nav[0].encodedBodySize || 0;
      }
      return sum;
    } catch {
      return 0;
    }
  }

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function copyToClipboard(text, btnEl) {
    const done = () => {
      if (!btnEl) return;
      const prev = btnEl.textContent;
      btnEl.textContent = '✓ 已複製';
      setTimeout(() => {
        btnEl.textContent = prev;
      }, 1400);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    } else {
      fallbackCopy(text, done);
    }
  }

  function fallbackCopy(text, done) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch {}
    ta.remove();
    done();
  }

  function buildFullReportText(st, displayBytes) {
    const lines = [
      `請幫我分析以下網站的資安狀態是否安全：`,
      `網站網域：${st.mainDomain || location.hostname}`,
      `狀態判定：${st.status.label}（${st.status.reason || '無'}）`,
      `HTTPS：${st.isHttps ? '是' : '否'} | 總大小：${formatBytes(displayBytes)} | 連線數：${st.requestCount}`
    ];
    if (st.keyloggers.length) {
      lines.push(`\n[側錄警報]`);
      st.keyloggers.forEach((k) => {
        lines.push(`- 監聽 ${k.eventType} (${k.targetDesc}) 來源：${k.scriptUrl}`);
      });
    }
    if (st.threatHits && st.threatHits.length) {
      lines.push(`\n[黑金封鎖命中]`);
      st.threatHits.forEach((h) => {
        lines.push(`- [${h.category}] ${h.target} (清單：${h.listName})`);
      });
    }
    const cnConns = st.connections.filter((c) => c.isCN);
    if (cnConns.length) {
      lines.push(`\n[大陸 IP 連線]`);
      cnConns.forEach((c) => lines.push(`- ${c.domain} (${c.ip})`));
    }
    if (st.redirects.length) {
      lines.push(`\n[跳板轉址]`);
      st.redirects.forEach((r) => lines.push(`- ${r.statusCode}: ${r.from} -> ${r.to}`));
    }
    if (st.suspiciousDownloads.length) {
      lines.push(`\n[可疑下載]`);
      st.suspiciousDownloads.forEach((d) => lines.push(`- ${d.filename} (${d.url})`));
    }
    return lines.join('\n');
  }

  // Safe Close Mode (avoids fake X buttons by removing DOM directly in capture phase)
  function onSafeMouseOver(e) {
    if (!safeCloseMode) return;
    const target = e.target;
    if (!target || target === hostEl || hostEl?.contains(target)) return;
    if (target === document.documentElement || target === document.body) return;
    if (highlightedEl && highlightedEl !== target) {
      highlightedEl.style.outline = origOutline;
    }
    highlightedEl = target;
    origOutline = target.style.outline;
    target.style.outline = '3px dashed #ef4444';
  }

  function onSafeClick(e) {
    if (!safeCloseMode) return;
    const target = e.target;
    if (target === hostEl || hostEl?.contains(target)) return;
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    if (target && target !== document.documentElement && target !== document.body) {
      target.remove();
      // Unlock page scroll if an overlay locked it
      if (document.body && getComputedStyle(document.body).overflow === 'hidden') {
        document.body.style.setProperty('overflow', 'auto', 'important');
      }
      if (document.documentElement && getComputedStyle(document.documentElement).overflow === 'hidden') {
        document.documentElement.style.setProperty('overflow', 'auto', 'important');
      }
    }
    highlightedEl = null;
  }

  function onSafeKeyDown(e) {
    if (safeCloseMode && e.key === 'Escape') {
      toggleSafeCloseMode(false);
    }
  }

  function toggleSafeCloseMode(force) {
    safeCloseMode = typeof force === 'boolean' ? force : !safeCloseMode;
    if (safeCloseMode) {
      document.addEventListener('mouseover', onSafeMouseOver, true);
      document.addEventListener('click', onSafeClick, true);
      document.addEventListener('keydown', onSafeKeyDown, true);
      document.documentElement.style.cursor = 'crosshair';
    } else {
      document.removeEventListener('mouseover', onSafeMouseOver, true);
      document.removeEventListener('click', onSafeClick, true);
      document.removeEventListener('keydown', onSafeKeyDown, true);
      document.documentElement.style.cursor = '';
      if (highlightedEl) {
        highlightedEl.style.outline = origOutline;
        highlightedEl = null;
      }
    }
    renderUI();
  }

  function ensureUI() {
    if (hostEl) return true;
    const parent = document.documentElement || document.body;
    if (!parent) return false;

    hostEl = document.createElement('div');
    hostEl.id = 'webguard-island-host';
    hostEl.style.cssText = 'all: initial; position: fixed; top: 14px; right: 18px; z-index: 2147483647;';
    shadow = hostEl.attachShadow({ mode: 'open' });

    const style = document.createElement('style');
    style.textContent = `
      * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans TC", sans-serif; }
      .wg-wrap { user-select: none; color: #f8fafc; }
      .wg-pill {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 7px 14px; border-radius: 999px;
        background: rgba(15, 23, 42, 0.92);
        backdrop-filter: blur(12px);
        cursor: pointer; font-size: 12px; font-weight: 600;
        box-shadow: 0 6px 20px rgba(0,0,0,0.35), 0 0 0 1px rgba(255,255,255,0.18);
        transition: all 0.22s ease;
      }
      .wg-pill.wg-circle {
        width: 30px; height: 30px; padding: 0;
        justify-content: center; gap: 0;
        border-radius: 50%;
      }
      .wg-pill.wg-circle .wg-dot {
        width: 11px; height: 11px;
      }
      .wg-pill:hover { transform: translateY(-1px); }
      .wg-pill.level-green { border: 2.5px solid #22c55e; }
      .wg-pill.level-orange { border: 2.5px solid #f97316; }
      .wg-pill.level-black { border: 2.5px solid #000000; box-shadow: 0 6px 20px rgba(0,0,0,0.55), 0 0 0 1.5px rgba(255,255,255,0.65); }
      .wg-pill.level-blackgold {
        background: linear-gradient(135deg, #09090b 0%, #1c1917 100%);
        border: 2.5px solid #d4af37;
        color: #fde68a;
        box-shadow: 0 6px 20px rgba(212,175,55,0.35), 0 0 0 1px rgba(251,191,36,0.4);
      }
      .wg-pill.level-red { border: 2.5px solid #ef4444; animation: wg-pulse 1.6s infinite; }

      @keyframes wg-pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0.55), 0 6px 20px rgba(0,0,0,0.35); }
        50% { box-shadow: 0 0 0 6px rgba(239,68,68,0), 0 6px 20px rgba(0,0,0,0.35); }
      }

      .wg-dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
      .level-green .wg-dot { background: #22c55e; }
      .level-orange .wg-dot { background: #f97316; }
      .level-black .wg-dot { background: #0f172a; border: 1.5px solid #e2e8f0; }
      .level-blackgold .wg-dot { background: #fbbf24; box-shadow: 0 0 6px #fbbf24; }
      .level-red .wg-dot { background: #ef4444; }

      .wg-meta { color: #94a3b8; font-weight: 500; font-size: 11px; }

      .wg-ko-pill-btn {
        margin-left: 2px;
        padding: 3px 8px;
        border-radius: 999px;
        border: 1px solid rgba(249, 115, 22, 0.55);
        background: rgba(249, 115, 22, 0.18);
        color: #fdba74;
        font-size: 11px;
        font-weight: 700;
        cursor: pointer;
        transition: all 0.15s ease;
      }
      .wg-ko-pill-btn:hover {
        background: #f97316;
        color: #fff;
      }
      .wg-ko-pill-btn.active {
        background: #ef4444;
        border-color: #ef4444;
        color: #fff;
      }

      .wg-panel {
        width: 360px; max-height: 520px; overflow: hidden;
        display: flex; flex-direction: column;
        border-radius: 18px;
        background: rgba(15, 23, 42, 0.96);
        backdrop-filter: blur(16px);
        box-shadow: 0 16px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.14);
        font-size: 12px;
      }
      .wg-panel.level-green { border: 2px solid #22c55e; }
      .wg-panel.level-orange { border: 2px solid #f97316; }
      .wg-panel.level-black { border: 2px solid #000000; box-shadow: 0 16px 40px rgba(0,0,0,0.6), 0 0 0 1.5px rgba(255,255,255,0.5); }
      .wg-panel.level-blackgold {
        background: rgba(9, 9, 11, 0.97);
        border: 2px solid #d4af37;
        box-shadow: 0 16px 40px rgba(212,175,55,0.28), 0 0 0 1px rgba(251,191,36,0.35);
      }
      .wg-panel.level-red { border: 2px solid #ef4444; }

      .wg-header {
        display: flex; align-items: center; justify-content: space-between;
        padding: 12px 14px; border-bottom: 1px solid rgba(255,255,255,0.08);
        cursor: move;
      }
      .wg-title-group { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
      .wg-status-title { font-weight: 700; font-size: 13px; display: flex; align-items: center; gap: 6px; }
      .wg-domain { font-size: 11px; color: #94a3b8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 250px; }
      .wg-close-btn {
        background: rgba(255,255,255,0.1); border: none; color: #e2e8f0;
        width: 24px; height: 24px; border-radius: 50%; cursor: pointer; font-size: 13px;
      }
      .wg-close-btn:hover { background: rgba(255,255,255,0.2); }

      .wg-stats {
        display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px;
        padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.08);
      }
      .wg-stat {
        background: rgba(255,255,255,0.05); border-radius: 10px; padding: 7px 6px; text-align: center;
      }
      .wg-stat-val { font-size: 13px; font-weight: 700; color: #f8fafc; }
      .wg-stat-lbl { font-size: 10px; color: #94a3b8; margin-top: 2px; }

      .wg-actions {
        display: flex; gap: 8px; padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,0.08);
      }
      .wg-btn {
        flex: 1; padding: 7px 8px; border-radius: 9px; border: 1px solid rgba(255,255,255,0.15);
        background: rgba(255,255,255,0.07); color: #f8fafc; font-size: 11px; font-weight: 600;
        cursor: pointer; text-align: center;
      }
      .wg-btn:hover { background: rgba(255,255,255,0.14); }
      .wg-btn.active { background: #ef4444; border-color: #ef4444; color: #fff; }

      .wg-tabs {
        display: flex; padding: 0 12px; border-bottom: 1px solid rgba(255,255,255,0.08);
      }
      .wg-tab {
        flex: 1; padding: 8px 4px; text-align: center; font-size: 11px; font-weight: 600;
        color: #94a3b8; cursor: pointer; border-bottom: 2px solid transparent;
      }
      .wg-tab.active { color: #38bdf8; border-bottom-color: #38bdf8; }

      .wg-body {
        overflow-y: auto; max-height: 240px; padding: 8px 12px;
      }
      .wg-row {
        display: flex; align-items: center; justify-content: space-between; gap: 6px;
        padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.05);
      }
      .wg-row:last-child { border-bottom: none; }
      .wg-row-main { min-width: 0; flex: 1; }
      .wg-row-domain { font-size: 11px; font-weight: 600; color: #e2e8f0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .wg-row-sub { font-size: 10px; color: #94a3b8; display: flex; gap: 6px; align-items: center; margin-top: 2px; }
      .wg-badge {
        padding: 1px 5px; border-radius: 4px; font-size: 9px; font-weight: 700;
      }
      .wg-badge-cn { background: #000; color: #fff; border: 1px solid #64748b; }
      .wg-badge-ad { background: #f97316; color: #fff; }
      .wg-badge-red { background: #ef4444; color: #fff; }
      .wg-badge-blackgold { background: #09090b; color: #fbbf24; border: 1px solid #d4af37; }
      .wg-block-btn {
        background: rgba(239,68,68,0.18); color: #fca5a5; border: 1px solid rgba(239,68,68,0.4);
        border-radius: 6px; padding: 3px 7px; font-size: 10px; cursor: pointer; flex-shrink: 0;
      }
      .wg-block-btn:hover { background: #ef4444; color: #fff; }
      .wg-copy-btn {
        background: rgba(56,189,248,0.16); color: #bae6fd; border: 1px solid rgba(56,189,248,0.38);
        border-radius: 6px; padding: 3px 7px; font-size: 10px; cursor: pointer; flex-shrink: 0;
      }
      .wg-copy-btn:hover { background: #0284c7; color: #fff; }
      .wg-row-actions { display: flex; gap: 4px; align-items: center; flex-shrink: 0; }
      .wg-empty { text-align: center; color: #64748b; padding: 18px 8px; font-size: 11px; }
      .wg-safe-banner {
        margin-top: 6px; padding: 6px 10px; border-radius: 10px;
        background: rgba(239,68,68,0.92); color: #fff; font-size: 11px; font-weight: 600;
        text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      }
    `;

    const container = document.createElement('div');
    container.className = 'wg-wrap';
    shadow.appendChild(style);
    shadow.appendChild(container);
    parent.appendChild(hostEl);

    enableDrag(hostEl);

    hostEl.addEventListener('mouseenter', () => {
      isHovering = true;
      if (shrinkTimer) {
        clearTimeout(shrinkTimer);
        shrinkTimer = null;
      }
      if (isMinimized) {
        isMinimized = false;
        renderUI();
      }
    });

    hostEl.addEventListener('mouseleave', () => {
      isHovering = false;
      scheduleShrink();
    });

    if (pageLoaded) {
      scheduleShrink();
    }
    return true;
  }

  function scheduleShrink() {
    if (shrinkTimer) clearTimeout(shrinkTimer);
    if (!pageLoaded || isExpanded || safeCloseMode || isHovering) return;
    shrinkTimer = setTimeout(() => {
      shrinkTimer = null;
      if (pageLoaded && !isExpanded && !safeCloseMode && !isHovering) {
        isMinimized = true;
        renderUI();
      }
    }, 3000);
  }

  function enableDrag(el) {
    let isDragging = false;
    let moved = false;
    let startX = 0;
    let startY = 0;
    let origRight = 18;
    let origTop = 14;

    el.addEventListener('mousedown', (e) => {
      const path = e.composedPath();
      const target = path[0];
      // Don't start drag on buttons/tabs/scrollable body
      if (target && (target.tagName === 'BUTTON' || target.closest?.('.wg-body') || target.closest?.('.wg-tabs'))) {
        return;
      }
      isDragging = true;
      moved = false;
      startX = e.clientX;
      startY = e.clientY;
      origRight = parseFloat(el.style.right) || 18;
      origTop = parseFloat(el.style.top) || 14;
    });

    window.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      const dx = e.clientX - startX;
      const dy = e.clientY - startY;
      if (Math.abs(dx) > 4 || Math.abs(dy) > 4) moved = true;
      if (!moved) return;
      el.style.right = `${Math.max(6, origRight - dx)}px`;
      el.style.top = `${Math.max(6, origTop + dy)}px`;
    });

    window.addEventListener('mouseup', () => {
      if (isDragging && moved) {
        el.dataset.justDragged = '1';
        setTimeout(() => { delete el.dataset.justDragged; }, 80);
      }
      isDragging = false;
    });
  }

  function renderUI() {
    if (!ensureUI()) return;
    const container = shadow.querySelector('.wg-wrap');
    if (!container) return;

    const st = currentState || {
      mainDomain: location.hostname,
      isHttps: location.protocol === 'https:',
      status: { level: 'green', label: '偵測中', reason: '' },
      requestCount: 0,
      totalBytes: 0,
      thirdPartyCount: 0,
      cnCount: 0,
      cnCacheCount: 0,
      redirects: [],
      keyloggers: [],
      suspiciousDownloads: [],
      connections: [],
      isWhitelisted: false
    };

    if (st.isWhitelisted && !isExpanded) {
      container.innerHTML = `
        <div class="wg-pill level-green" id="wg-pill-btn" title="已隱藏此站警示（點擊展開）">
          <span class="wg-dot"></span>
          <span>已忽略</span>
        </div>
      `;
      bindEvents(st);
      return;
    }

    const displayBytes = Math.max(st.totalBytes || 0, getPerfPageBytes());
    const levelClass = `level-${st.status.level}`;

    if (!isExpanded) {
      if (isMinimized && !safeCloseMode && !isHovering) {
        container.innerHTML = `
          <div class="wg-pill wg-circle ${levelClass}" id="wg-pill-btn" title="${escapeHtml(st.status.label)} - ${escapeHtml(st.status.reason)}">
            <span class="wg-dot"></span>
          </div>
        `;
        bindEvents(st);
        return;
      }
      container.innerHTML = `
        <div class="wg-pill ${levelClass}" id="wg-pill-btn" title="${escapeHtml(st.status.reason)}">
          <span class="wg-dot"></span>
          <span>${escapeHtml(st.status.label)}</span>
          <span class="wg-meta">${st.requestCount} 連線 · ${formatBytes(displayBytes)}</span>
          <button class="wg-ko-pill-btn ${safeCloseMode ? 'active' : ''}" id="wg-ko-pill-btn" title="免點假X：啟動後直接點廣告即可移除 (ESC 退出)">
            ${safeCloseMode ? '🛑 KO 中' : '🥊 KO 廣告'}
          </button>
        </div>
        ${safeCloseMode ? '<div class="wg-safe-banner">🥊 KO 廣告模式：點選蓋版廣告直接移除 (ESC 退出)</div>' : ''}
      `;
      bindEvents(st);
      return;
    }

    // Expanded panel
    let bodyHtml = '';
    if (activeTab === 'connections') {
      if (!st.connections.length) {
        bodyHtml = '<div class="wg-empty">尚無外部連線紀錄</div>';
      } else {
        bodyHtml = st.connections
          .map((c) => {
            const badges = [];
            if (c.isCN) badges.push('<span class="wg-badge wg-badge-cn">CN 大陸IP</span>');
            else if (c.countryCode) badges.push(`<span class="wg-badge" style="background:#334155;color:#e2e8f0;">${escapeHtml(c.countryCode)}</span>`);
            if (c.isAd) badges.push('<span class="wg-badge wg-badge-ad">廣告/追蹤</span>');
            const isMain = c.domain === st.mainDomain;
            const copyText = `請幫我確認在「${st.mainDomain || location.hostname}」連出的這個第三方網域與 IP 是否安全：\n網域：${c.domain}\nIP：${c.ip || '未知'} (${c.countryCode || '未知地區'})`;
            return `
              <div class="wg-row">
                <div class="wg-row-main">
                  <div class="wg-row-domain">${escapeHtml(c.domain)}</div>
                  <div class="wg-row-sub">
                    <span>${escapeHtml(c.ip || '解析中')}</span>
                    ${badges.join('')}
                    <span>${c.count}次 · ${formatBytes(c.bytes)}</span>
                  </div>
                </div>
                <div class="wg-row-actions">
                  <button class="wg-copy-btn" data-copy="${escapeHtml(copyText)}" title="複製去問 Gemini / Google">📋</button>
                  ${isMain ? '' : `<button class="wg-block-btn" data-block="${escapeHtml(c.domain)}">封鎖</button>`}
                </div>
              </div>
            `;
          })
          .join('');
      }
    } else {
      const items = [];
      for (const h of (st.threatHits || [])) {
        const copyText = `請幫我確認在「${st.mainDomain || location.hostname}」被黑金清單直接封鎖的這個目標：\n目標：${h.target}\n分類：${h.category}\n清單來源：${h.listName}`;
        items.push(`
          <div class="wg-row">
            <div class="wg-row-main">
              <div class="wg-row-domain"><span class="wg-badge wg-badge-blackgold">黑金已封鎖</span> ${escapeHtml(h.target)}</div>
              <div class="wg-row-sub">${escapeHtml(h.category)} · ${escapeHtml(h.listName)}</div>
            </div>
            <div class="wg-row-actions">
              <button class="wg-copy-btn" data-copy="${escapeHtml(copyText)}" title="複製去問 Gemini / Google">📋</button>
            </div>
          </div>
        `);
      }
      for (const k of st.keyloggers) {
        const copyText = `請幫我檢查在「${st.mainDomain || location.hostname}」偵測到的這個腳本是否安全：\n類型：側錄警報 監聽 ${k.eventType} (${k.targetDesc})\n來源腳本：${k.scriptUrl}`;
        items.push(`
          <div class="wg-row">
            <div class="wg-row-main">
              <div class="wg-row-domain"><span class="wg-badge wg-badge-red">側錄警報</span> 監聽 ${escapeHtml(k.eventType)} (${escapeHtml(k.targetDesc)})</div>
              <div class="wg-row-sub">${escapeHtml(k.scriptUrl)}</div>
            </div>
            <div class="wg-row-actions">
              <button class="wg-copy-btn" data-copy="${escapeHtml(copyText)}" title="複製去問 Gemini / Google">📋</button>
            </div>
          </div>
        `);
      }
      for (const d of st.suspiciousDownloads) {
        const copyText = `請幫我檢查在「${st.mainDomain || location.hostname}」觸發的這個下載是否安全：\n檔名：${d.filename}\n網址：${d.url}`;
        items.push(`
          <div class="wg-row">
            <div class="wg-row-main">
              <div class="wg-row-domain"><span class="wg-badge wg-badge-ad">可疑下載</span> ${escapeHtml(d.filename)}</div>
              <div class="wg-row-sub">${escapeHtml(d.url)}</div>
            </div>
            <div class="wg-row-actions">
              <button class="wg-copy-btn" data-copy="${escapeHtml(copyText)}" title="複製去問 Gemini / Google">📋</button>
            </div>
          </div>
        `);
      }
      for (const r of st.redirects) {
        const copyText = `請幫我檢查在「${st.mainDomain || location.hostname}」的這個跳板轉址是否安全：\n狀態碼：${r.statusCode}\n從：${r.from}\n到：${r.to}`;
        items.push(`
          <div class="wg-row">
            <div class="wg-row-main">
              <div class="wg-row-domain"><span class="wg-badge wg-badge-ad">跳板 ${r.statusCode}</span></div>
              <div class="wg-row-sub" style="display:block; word-break:break-all;">${escapeHtml(r.from)} → ${escapeHtml(r.to)}</div>
            </div>
            <div class="wg-row-actions">
              <button class="wg-copy-btn" data-copy="${escapeHtml(copyText)}" title="複製去問 Gemini / Google">📋</button>
            </div>
          </div>
        `);
      }
      bodyHtml = items.length ? items.join('') : '<div class="wg-empty">未偵測到側錄腳本、跳板或可疑下載</div>';
    }

    container.innerHTML = `
      <div class="wg-panel ${levelClass}">
        <div class="wg-header">
          <div class="wg-title-group">
            <div class="wg-status-title">
              <span class="wg-dot"></span>
              <span>${escapeHtml(st.status.label)}</span>
            </div>
            <div class="wg-domain">${st.isHttps ? '🔒' : '⚠️ HTTP'} ${escapeHtml(st.mainDomain || location.hostname)}</div>
          </div>
          <button class="wg-close-btn" id="wg-collapse-btn" title="收合">✕</button>
        </div>
        <div class="wg-stats">
          <div class="wg-stat">
            <div class="wg-stat-val">${formatBytes(displayBytes)}</div>
            <div class="wg-stat-lbl">網站大小</div>
          </div>
          <div class="wg-stat">
            <div class="wg-stat-val">${st.requestCount}</div>
            <div class="wg-stat-lbl">最近連線</div>
          </div>
          <div class="wg-stat">
            <div class="wg-stat-val">${st.cnCount}</div>
            <div class="wg-stat-lbl">大陸IP (記${st.cnCacheCount})</div>
          </div>
          <div class="wg-stat">
            <div class="wg-stat-val">${st.redirects.length}</div>
            <div class="wg-stat-lbl">跳轉次數</div>
          </div>
        </div>
        <div class="wg-actions">
          <button class="wg-btn ${safeCloseMode ? 'active' : ''}" id="wg-safe-close-btn">
            ${safeCloseMode ? '🛑 結束 KO (ESC)' : '🥊 KO 廣告'}
          </button>
          <button class="wg-btn" id="wg-copy-all-btn" title="複製完整報告去問 Gemini / Google">📋 複製報告</button>
          <button class="wg-btn" id="wg-open-lists-btn" title="開啟清單管理網頁手動更新">🔄 更新清單</button>
          <button class="wg-btn" id="wg-whitelist-btn">
            ${st.isWhitelisted ? '👁️ 恢復' : '🙈 忽略'}
          </button>
        </div>
        <div class="wg-tabs">
          <div class="wg-tab ${activeTab === 'threats' ? 'active' : ''}" data-tab="threats">已封鎖與威脅 (${(st.threatHits?.length || 0) + st.keyloggers.length + st.redirects.length + st.suspiciousDownloads.length})</div>
          <div class="wg-tab ${activeTab === 'connections' ? 'active' : ''}" data-tab="connections">連線與 IP (${st.connections.length})</div>
        </div>
        <div class="wg-body">${bodyHtml}</div>
      </div>
    `;
    bindEvents(st, displayBytes);
  }

  function bindEvents(st, displayBytes = 0) {
    const koPillBtn = shadow.getElementById('wg-ko-pill-btn');
    if (koPillBtn) {
      koPillBtn.onclick = (e) => {
        e.stopPropagation();
        toggleSafeCloseMode();
      };
    }

    const pillBtn = shadow.getElementById('wg-pill-btn');
    if (pillBtn) {
      pillBtn.onclick = () => {
        if (hostEl.dataset.justDragged) return;
        isExpanded = true;
        renderUI();
      };
    }

    const collapseBtn = shadow.getElementById('wg-collapse-btn');
    if (collapseBtn) {
      collapseBtn.onclick = () => {
        isExpanded = false;
        renderUI();
        scheduleShrink();
      };
    }

    const safeBtn = shadow.getElementById('wg-safe-close-btn');
    if (safeBtn) {
      safeBtn.onclick = () => toggleSafeCloseMode();
    }

    const copyAllBtn = shadow.getElementById('wg-copy-all-btn');
    if (copyAllBtn) {
      copyAllBtn.onclick = () => {
        copyToClipboard(buildFullReportText(st, displayBytes), copyAllBtn);
      };
    }

    const openListsBtn = shadow.getElementById('wg-open-lists-btn');
    if (openListsBtn) {
      openListsBtn.onclick = () => {
        chrome.runtime.sendMessage({ type: 'WEBGUARD_OPEN_LISTS_PAGE' });
      };
    }

    const wlBtn = shadow.getElementById('wg-whitelist-btn');
    if (wlBtn) {
      wlBtn.onclick = () => {
        chrome.runtime.sendMessage({
          type: 'WEBGUARD_TOGGLE_WHITELIST',
          domain: st.mainDomain || location.hostname
        });
      };
    }

    shadow.querySelectorAll('.wg-tab').forEach((tabEl) => {
      tabEl.onclick = () => {
        activeTab = tabEl.dataset.tab;
        renderUI();
      };
    });

    shadow.querySelectorAll('.wg-copy-btn').forEach((btn) => {
      btn.onclick = () => {
        copyToClipboard(btn.dataset.copy || '', btn);
      };
    });

    shadow.querySelectorAll('.wg-block-btn').forEach((btn) => {
      btn.onclick = () => {
        const domain = btn.dataset.block;
        chrome.runtime.sendMessage({ type: 'WEBGUARD_BLOCK_DOMAIN', domain }, () => {
          btn.textContent = '已封鎖';
          btn.disabled = true;
        });
      };
    });
  }

  // Initial fetch & periodic refresh for performance bytes
  function requestState() {
    chrome.runtime.sendMessage({ type: 'WEBGUARD_GET_STATE' }, (res) => {
      if (res && res.ok && res.payload) {
        currentState = res.payload;
        renderUI();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      ensureUI();
      requestState();
    });
  } else {
    ensureUI();
    requestState();
  }

  if (document.readyState !== 'complete') {
    window.addEventListener('load', () => {
      pageLoaded = true;
      requestState();
      scheduleShrink();
    });
  }
  setTimeout(requestState, 1200);
})();
