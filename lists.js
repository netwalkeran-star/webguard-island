let currentBlockedDomains = [];
let currentListsMeta = [];

function formatTime(ts) {
  if (!ts) return '尚未更新';
  try {
    return new Date(ts).toLocaleString('zh-TW');
  } catch {
    return String(ts);
  }
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function copyText(text, btn) {
  const showDone = () => {
    if (!btn) return;
    const prev = btn.textContent;
    btn.textContent = '✓ 已複製 AI 指令';
    setTimeout(() => { btn.textContent = prev; }, 1500);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(showDone).catch(() => {});
  }
}

function renderBlockedDomains(domains) {
  currentBlockedDomains = domains || [];
  document.getElementById('user-blocked-count').textContent = currentBlockedDomains.length;
  const box = document.getElementById('user-blocked-list');
  if (!currentBlockedDomains.length) {
    box.innerHTML = '<div style="color:#71717a;padding:8px;">目前尚無手動封鎖的網域</div>';
    return;
  }
  box.innerHTML = '';
  currentBlockedDomains.forEach((domain) => {
    const row = document.createElement('div');
    row.className = 'match-row';
    row.style.alignItems = 'center';

    const left = document.createElement('span');
    left.style.fontWeight = '700';
    left.style.color = '#fca5a5';
    left.textContent = domain;

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.gap = '8px';

    const aiBtn = document.createElement('button');
    aiBtn.className = 'btn';
    aiBtn.style.padding = '4px 10px';
    aiBtn.style.fontSize = '11px';
    aiBtn.textContent = '🤖 AI 分析';
    aiBtn.onclick = () => {
      const prompt = `請幫我分析這個我手動封鎖的網域「${domain}」：\n1. 它屬於什麼服務或用途？（例如：廣告追蹤、CDN、分析工具、詐騙／惡意網域、或正常網站功能）\n2. 封鎖它會不會影響正常網站運作？建議保留封鎖還是解除封鎖？`;
      copyText(prompt, aiBtn);
    };

    const unblockBtn = document.createElement('button');
    unblockBtn.className = 'btn';
    unblockBtn.style.padding = '4px 10px';
    unblockBtn.style.fontSize = '11px';
    unblockBtn.style.borderColor = '#ef4444';
    unblockBtn.style.color = '#fca5a5';
    unblockBtn.textContent = '解除封鎖';
    unblockBtn.onclick = () => {
      chrome.runtime.sendMessage({ type: 'WEBGUARD_UNBLOCK_DOMAIN', domain }, (res) => {
        if (res && res.ok) renderBlockedDomains(res.blockedDomains);
      });
    };

    actions.appendChild(aiBtn);
    actions.appendChild(unblockBtn);
    row.appendChild(left);
    row.appendChild(actions);
    box.appendChild(row);
  });
}

function renderLists(data) {
  if (!data || !data.ok) return;
  currentListsMeta = data.lists || [];
  document.getElementById('total-domains').textContent = (data.totalDomains || 0).toLocaleString();
  document.getElementById('total-ips').textContent = (data.totalIps || 0).toLocaleString();
  if (Array.isArray(data.blockedDomains)) {
    renderBlockedDomains(data.blockedDomains);
  }

  const tbody = document.getElementById('lists-tbody');
  tbody.innerHTML = data.lists
    .map((item) => {
      let statusHtml = `<span class="status-none">尚未下載</span>`;
      if (item.error) {
        statusHtml = `<span class="status-err">失敗：${escapeHtml(item.error)}</span>`;
      } else if (item.updatedAt) {
        statusHtml = `<span class="status-ok">${escapeHtml(formatTime(item.updatedAt))}</span>`;
      }

      return `
        <tr>
          <td><span class="cat-badge">${escapeHtml(item.category)}</span></td>
          <td>
            <div style="font-weight:700;color:#f8fafc;">${escapeHtml(item.name)}</div>
            <div class="url-text">${escapeHtml(item.url)}</div>
          </td>
          <td style="font-weight:700;color:#fbbf24;">${(item.count || 0).toLocaleString()}</td>
          <td>${statusHtml}</td>
          <td>
            <button class="btn single-update-btn" data-id="${escapeHtml(item.id)}">更新</button>
          </td>
        </tr>
      `;
    })
    .join('');

  document.querySelectorAll('.single-update-btn').forEach((btn) => {
    btn.onclick = () => triggerUpdate(btn.dataset.id, btn);
  });
}

function loadListsInfo() {
  chrome.runtime.sendMessage({ type: 'WEBGUARD_GET_LISTS_INFO' }, renderLists);
}

function triggerUpdate(id, triggerBtn) {
  const allBtns = document.querySelectorAll('button');
  allBtns.forEach((b) => { b.disabled = true; });
  const origText = triggerBtn.textContent;
  triggerBtn.textContent = '更新中...';

  chrome.runtime.sendMessage({ type: 'WEBGUARD_UPDATE_LIST', id }, (res) => {
    allBtns.forEach((b) => { b.disabled = false; });
    triggerBtn.textContent = origText;
    if (res) {
      renderLists(res);
      const toast = document.getElementById('update-toast');
      if (toast) toast.style.display = 'block';
    }
  });
}

document.getElementById('update-all-btn').onclick = function () {
  triggerUpdate('all', this);
};

function runSearch() {
  const q = document.getElementById('search-input').value.trim();
  const box = document.getElementById('search-results');
  if (!q) {
    box.innerHTML = '';
    return;
  }
  chrome.runtime.sendMessage({ type: 'WEBGUARD_SEARCH_LIST', query: q }, (res) => {
    if (!res || !res.ok || !res.matches.length) {
      box.innerHTML = '<div style="color:#71717a;padding:8px;">本地黑名單中查無符合項目（若尚未更新清單，請先點擊上方「全部手動更新」）</div>';
      return;
    }
    box.innerHTML = res.matches
      .map(
        (m) => `
          <div class="match-row">
            <span style="font-weight:700;color:#fbbf24;">${escapeHtml(m.target)}</span>
            <span style="color:#a1a1aa;">${escapeHtml(m.category)} · ${escapeHtml(m.listName)}</span>
          </div>
        `
      )
      .join('');
  });
}

document.getElementById('search-btn').onclick = runSearch;
document.getElementById('search-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runSearch();
});

document.getElementById('copy-ai-prompt-btn').onclick = function () {
  const lines = [
    '請擔任資安分析師，幫我分析以下我的瀏覽器封鎖清單：',
    ''
  ];
  if (currentBlockedDomains.length) {
    lines.push(`【我手動封鎖的網域列表（共 ${currentBlockedDomains.length} 筆）】`);
    currentBlockedDomains.forEach((d, idx) => lines.push(`${idx + 1}. ${d}`));
    lines.push('');
    lines.push('請針對上述手動封鎖的網域逐一說明：');
    lines.push('1. 各自屬於什麼服務或用途（廣告追蹤 / 惡意 / 正常 CDN 或功能）？');
    lines.push('2. 有哪些可能是誤封、建議解除封鎖的網域？');
  } else {
    lines.push('（目前尚未手動封鎖任何網域）');
  }
  if (currentListsMeta.length) {
    lines.push('');
    lines.push('【目前啟用的外部黑金封鎖清單摘要】');
    currentListsMeta.forEach((m) => {
      lines.push(`- ${m.category}｜${m.name}：${m.count || 0} 筆`);
    });
  }
  copyText(lines.join('\n'), this);
};

loadListsInfo();
