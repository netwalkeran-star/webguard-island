function refreshSettings() {
  chrome.runtime.sendMessage({ type: 'WEBGUARD_GET_SETTINGS' }, (res) => {
    if (!res || !res.ok) return;
    document.getElementById('threat-total').textContent = (res.threatListTotal || 0).toLocaleString();
    document.getElementById('cn-count').textContent = res.cnCacheCount || 0;
    document.getElementById('geoip-count').textContent = res.geoipCacheCount || 0;

    const blocked = res.blockedDomains || [];
    document.getElementById('blocked-count').textContent = blocked.length;
    const blockedList = document.getElementById('blocked-list');
    if (!blocked.length) {
      blockedList.innerHTML = '<div class="muted">尚無封鎖網域</div>';
    } else {
      blockedList.innerHTML = '';
      blocked.forEach((domain) => {
        const row = document.createElement('div');
        row.className = 'item';
        const span = document.createElement('span');
        span.textContent = domain;
        const btn = document.createElement('button');
        btn.textContent = '解除';
        btn.onclick = () => {
          chrome.runtime.sendMessage({ type: 'WEBGUARD_UNBLOCK_DOMAIN', domain }, refreshSettings);
        };
        row.appendChild(span);
        row.appendChild(btn);
        blockedList.appendChild(row);
      });
    }

    const wl = res.whitelistedDomains || [];
    document.getElementById('whitelist-count').textContent = wl.length;
    const wlList = document.getElementById('whitelist-list');
    if (!wl.length) {
      wlList.innerHTML = '<div class="muted">尚無忽略網站</div>';
    } else {
      wlList.innerHTML = '';
      wl.forEach((domain) => {
        const row = document.createElement('div');
        row.className = 'item';
        const span = document.createElement('span');
        span.textContent = domain;
        const btn = document.createElement('button');
        btn.textContent = '移除';
        btn.onclick = () => {
          chrome.runtime.sendMessage({ type: 'WEBGUARD_TOGGLE_WHITELIST', domain }, refreshSettings);
        };
        row.appendChild(span);
        row.appendChild(btn);
        wlList.appendChild(row);
      });
    }
  });
}

document.getElementById('open-lists-btn').onclick = () => {
  chrome.runtime.sendMessage({ type: 'WEBGUARD_OPEN_LISTS_PAGE' });
};

document.getElementById('clear-cache-btn').onclick = () => {
  chrome.runtime.sendMessage({ type: 'WEBGUARD_CLEAR_GEOIP_CACHE' }, refreshSettings);
};

refreshSettings();
