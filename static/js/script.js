/* ==========================================================================
   IoTShield front end
   Sections: 1 helpers · 2 layout · 3 dashboard · 4 devices · 5 authenticate
             6 logs · 7 device details · 8 about · 9 firmware
   The browser never receives a secret key: it only talks to the JSON API.
   ========================================================================== */
(() => {
  'use strict';

  /* ---------- 1. helpers ---------- */
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const CSRF = $('meta[name="csrf-token"]')?.content || '';
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

  const icon = (name) => `<svg class="icon"><use href="#i-${name}"/></svg>`;

  async function api(url, { method = 'GET', body } = {}) {
    const options = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
    if (method !== 'GET') options.headers['X-CSRF-Token'] = CSRF;
    if (body !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch(url, options);
    } catch (networkError) {
      throw new Error('Cannot reach the server. Is IoTShield still running?');
    }
    if (response.status === 401) {
      window.location.href = '/login';
      throw new Error('Session expired. Please log in again.');
    }
    let data = {};
    try { data = await response.json(); } catch (parseError) { /* keep empty */ }
    if (!response.ok) {
      const error = new Error(data.error || data.message || 'Something went wrong. Please try again.');
      error.data = data;
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function timeAgo(iso) {
    if (!iso) return 'Never';
    const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (seconds < 10) return 'Just now';
    if (seconds < 60) return `${Math.floor(seconds)} sec ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
    return `${Math.floor(seconds / 86400)} d ago`;
  }
  const fmtTime = (iso) => new Date(iso).toLocaleTimeString([], { hour12: false });
  const fmtDate = (iso) => new Date(iso).toLocaleDateString([], { day: '2-digit', month: 'short', year: 'numeric' });
  const fmtDateTime = (iso) => (iso ? `${fmtDate(iso)}, ${fmtTime(iso)}` : 'Never');

  const STATUS_LABEL = { online: 'Online', offline: 'Offline', authenticating: 'Authenticating', disabled: 'Disabled' };
  const statusBadge = (status) =>
    `<span class="status status-${status}"><i class="dot"></i>${STATUS_LABEL[status] || status}</span>`;
  const demoBadge = () => '';
  const FIRMWARE_STATUS = {
    up_to_date: '<span class="badge badge-success">UP TO DATE</span>',
    outdated: '<span class="badge badge-warn">UPDATE AVAILABLE</span>',
    unknown: '<span class="badge badge-muted">NOT REPORTED</span>',
  };
  const fwVersion = (version) => (version ? `<span class="mono">v${escapeHtml(version)}</span>` : '<span class="card-sub">—</span>');
  const resultBadge = (result) => result === 'SUCCESS'
    ? '<span class="badge badge-success">● SUCCESS</span>'
    : '<span class="badge badge-failed">● FAILED</span>';

  function toast(message, type = 'success', detail = '') {
    const symbol = { success: 'check-circle', error: 'x-circle', info: 'info' }[type];
    const element = document.createElement('div');
    element.className = `toast toast-${type}`;
    element.innerHTML = `${icon(symbol)}<div>${escapeHtml(message)}${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</div>`;
    $('#toasts').appendChild(element);
    setTimeout(() => {
      element.classList.add('out');
      setTimeout(() => element.remove(), 450);
    }, 4200);
  }

  function showModal(html, onClose) {
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.innerHTML = html;
    document.body.appendChild(backdrop);
    let closed = false;
    const close = () => {
      if (closed) return;
      closed = true;
      document.removeEventListener('keydown', onKey);
      backdrop.classList.add('closing');
      setTimeout(() => backdrop.remove(), 250);
      if (onClose) onClose();
    };
    const onKey = (event) => { if (event.key === 'Escape') close(); };
    document.addEventListener('keydown', onKey);
    backdrop.addEventListener('click', (event) => { if (event.target === backdrop) close(); });
    $$('[data-close]', backdrop).forEach((button) => button.addEventListener('click', close));
    return { element: backdrop, close };
  }

  function confirmDialog({ title, message, confirmText }) {
    return new Promise((resolve) => {
      let answer = false;
      const modal = showModal(`
        <div class="modal">
          <h2>${escapeHtml(title)}</h2>
          <p>${escapeHtml(message)}</p>
          <div class="modal-actions">
            <button class="btn" data-close>Cancel</button>
            <button class="btn btn-solid-danger" data-confirm>${escapeHtml(confirmText)}</button>
          </div>
        </div>`, () => resolve(answer));
      $('[data-confirm]', modal.element).addEventListener('click', () => { answer = true; modal.close(); });
    });
  }

  function animateNumber(element, value, { decimals = 0, suffix = '' } = {}) {
    const previous = element.dataset.value === undefined ? null : Number(element.dataset.value);
    if (previous === value) return;
    element.dataset.value = value;
    const from = previous === null ? 0 : previous;
    const start = performance.now();
    const step = (now) => {
      const progress = Math.min(1, (now - start) / 700);
      const eased = 1 - Math.pow(1 - progress, 3);
      element.textContent = (from + (value - from) * eased).toFixed(decimals) + suffix;
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  /** Run `task` now and then every `ms`, but only while the tab is visible. */
  function poll(task, ms) {
    task();
    setInterval(() => { if (!document.hidden) task(); }, ms);
  }

  /* ---------- 2. layout: menu, profile, theme, page transitions ---------- */
  const themeToggle = $('#themeToggle');
  if (themeToggle && document.documentElement.getAttribute('data-theme') === 'light') {
    themeToggle.setAttribute('aria-label', 'Switch to dark mode');
    themeToggle.setAttribute('title', 'Switch to dark mode');
  }
  themeToggle?.addEventListener('click', () => {
    const goingLight = document.documentElement.getAttribute('data-theme') !== 'light';
    document.documentElement.setAttribute('data-theme', goingLight ? 'light' : 'dark');
    const label = goingLight ? 'Switch to dark mode' : 'Switch to light mode';
    themeToggle.setAttribute('aria-label', label);
    themeToggle.setAttribute('title', label);
    try { localStorage.setItem('iotshield-theme', goingLight ? 'light' : 'dark'); } catch (e) { /* ignore */ }
  });

  $('#navToggle')?.addEventListener('click', () => $('#navLinks').classList.toggle('open'));
  $('#profileBtn')?.addEventListener('click', (event) => {
    event.stopPropagation();
    $('#profileMenu').classList.toggle('open');
  });
  document.addEventListener('click', () => $('#profileMenu')?.classList.remove('open'));

  document.addEventListener('click', (event) => {
    const link = event.target.closest('a[href]');
    if (!link || link.target === '_blank' || link.hasAttribute('data-no-transition')) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    const url = new URL(link.href, window.location.href);
    if (url.origin !== window.location.origin || url.pathname === window.location.pathname && url.search === window.location.search) return;
    event.preventDefault();
    document.body.classList.add('leaving');
    setTimeout(() => { window.location.href = url.href; }, 170);
  });
  window.addEventListener('pageshow', () => document.body.classList.remove('leaving'));

  /* ---------- idle timeout: sign out after 5 minutes without mouse / keyboard activity ---------- */
  const IDLE_LIMIT_MS = 5 * 60 * 1000;
  let lastInput = Date.now();
  let lastPing = Date.now();
  ['mousemove', 'mousedown', 'keydown', 'scroll', 'wheel', 'touchstart'].forEach((name) =>
    window.addEventListener(name, () => { lastInput = Date.now(); }, { passive: true }));

  function checkIdle() {
    const now = Date.now();
    if (now - lastInput >= IDLE_LIMIT_MS) {
      window.location.href = '/logout?reason=idle';
      return;
    }
    if (lastInput > lastPing) {           // tell the server the user is still here
      lastPing = now;
      api('/api/activity', { method: 'POST' }).catch(() => {});
    }
  }
  setInterval(checkIdle, 5000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) checkIdle(); });

  /* ---------- 3. dashboard: statistics, fleet, security status, activity, chart ---------- */
  function initDashboard() {
    let firstLoad = true;
    const VAULT_TEXT = {
      normal: 'Key stored in a file', sealed: 'Sealed: devices cannot authenticate',
      unsealed: 'Unsealed: key held in memory only', environment: 'Key supplied by the environment',
    };

    function renderChart(logs) {
      const buckets = [];
      for (let i = 11; i >= 0; i--) {
        const start = new Date(); start.setMinutes(0, 0, 0); start.setHours(start.getHours() - i);
        buckets.push({ start: start.getTime(), ok: 0, bad: 0 });
      }
      let inWindow = 0;
      logs.forEach((log) => {
        const time = new Date(log.timestamp).getTime();
        const bucket = buckets.find((item) => time >= item.start && time < item.start + 3600000);
        if (!bucket) return;
        inWindow += 1;
        if (log.result === 'SUCCESS') bucket.ok += 1; else bucket.bad += 1;
      });
      const peak = Math.max(1, ...buckets.map((item) => item.ok + item.bad));
      $('#chartTotal').textContent = `${inWindow} attempt${inWindow === 1 ? '' : 's'}`;
      $('#attemptChart').innerHTML = buckets.map((item) => {
        const hour = String(new Date(item.start).getHours()).padStart(2, '0');
        return `<div class="bar-col" title="${hour}:00 · ${item.ok} successful, ${item.bad} failed">
          <div class="bar-stack">
            <i class="bar bad" style="height:${(item.bad / peak) * 100}%"></i>
            <i class="bar ok" style="height:${(item.ok / peak) * 100}%"></i>
          </div><span>${hour}</span></div>`;
      }).join('');
    }

    async function refresh() {
      try {
        const [stats, deviceData, logData, firmware, vault] = await Promise.all([
          api('/api/stats'), api('/api/devices'), api('/api/logs'), api('/api/firmware'), api('/api/custody'),
        ]);

        animateNumber($('#statTotal'), stats.total_devices);
        animateNumber($('#statOnline'), stats.online_devices);
        animateNumber($('#statFailed'), stats.failed_attempts);
        animateNumber($('#statRate'), stats.success_rate, { decimals: 1, suffix: '%' });

        const versions = Object.fromEntries(firmware.devices.map((device) => [device.device_id, device]));
        $('#fleetBody').innerHTML = deviceData.devices.length
          ? deviceData.devices.map((device) => `
            <tr>
              <td><a class="dev-id" href="/devices/${encodeURIComponent(device.device_id)}">${escapeHtml(device.device_id)}</a>
                  <span class="sub">${escapeHtml(device.device_name)}</span></td>
              <td>${statusBadge(device.status)}</td>
              <td>${fwVersion(versions[device.device_id] && versions[device.device_id].firmware_version)}</td>
              <td>${timeAgo(device.last_authenticated)}</td>
            </tr>`).join('')
          : '<tr><td colspan="4" class="empty">No devices registered yet.</td></tr>';

        const sealed = vault.state === 'sealed';
        $('#secVault').innerHTML = `<span class="badge ${sealed ? 'badge-failed' : 'badge-success'}">${escapeHtml(vault.state)}</span>
          <span class="sub">${escapeHtml(VAULT_TEXT[vault.state] || '')}</span>`;
        $('#secShares').textContent = vault.shares ? `${vault.shares.threshold} of ${vault.shares.total} needed` : 'Not split yet';
        $('#secRotation').textContent = vault.rotated_at ? fmtDateTime(vault.rotated_at) : 'Never';
        $('#secFirmware').innerHTML = firmware.latest ? fwVersion(firmware.latest) : '<span class="card-sub">None published</span>';
        const upToDate = firmware.devices.filter((device) => device.firmware_status === 'up_to_date').length;
        $('#secOutdated').textContent = firmware.latest ? `${upToDate} of ${firmware.devices.length} devices up to date` : '–';
        $('#secBlocked').textContent = String(firmware.events.filter((event) => event.result === 'REJECTED').length);

        $('#activityList').innerHTML = logData.logs.length
          ? logData.logs.slice(0, 8).map((log) => `
            <div class="act-row">
              <span class="dot ${log.result === 'SUCCESS' ? 'ok' : 'bad'}"></span>
              <span class="dev-id">${escapeHtml(log.device_id)}</span>
              <span class="act-reason">${escapeHtml(log.reason || (log.result === 'SUCCESS' ? 'Authenticated' : 'Failed'))}</span>
              <span class="act-time">${timeAgo(log.timestamp)}</span>
            </div>`).join('')
          : '<p class="empty">No authentication attempts yet.</p>';

        renderChart(logData.logs);
        firstLoad = false;
      } catch (error) {
        if (firstLoad) toast(error.message, 'error');
      }
    }
    poll(refresh, 4000);
  }

  /* ---------- 4. devices ---------- */
  function initDevices() {
    const body = $('#devicesBody');
    const form = $('#addDeviceForm');
    let knownIds = null;

    async function load() {
      try {
        const { devices } = await api('/api/devices');
        const isNew = (id) => knownIds !== null && !knownIds.has(id);
        $('#deviceCount').textContent = `${devices.length} device${devices.length === 1 ? '' : 's'}`;
        body.innerHTML = devices.length ? devices.map((device) => `
          <tr class="${isNew(device.device_id) ? 'flash' : ''}">
            <td><span class="dev-id">${escapeHtml(device.device_id)}</span>${demoBadge(device.is_demo)}</td>
            <td>${escapeHtml(device.device_name)}</td>
            <td>${escapeHtml(device.device_type)}</td>
            <td>${statusBadge(device.status)}</td>
            <td>${fwVersion(device.firmware_version)}</td>
            <td>${device.attempts}</td>
            <td>${timeAgo(device.last_authenticated)}</td>
            <td><div class="actions">
              <a class="btn btn-sm" href="/devices/${encodeURIComponent(device.device_id)}">${icon('eye')}View</a>
              <a class="btn btn-sm" href="/authenticate?device=${encodeURIComponent(device.device_id)}">${icon('key')}Authenticate</a>
              <button class="btn btn-sm ${device.enabled ? 'btn-danger' : ''}" data-toggle="${escapeHtml(device.device_id)}">${icon('power')}${device.enabled ? 'Disable' : 'Enable'}</button>
            </div></td>
          </tr>`).join('') : '<tr><td colspan="8" class="empty">No devices yet. Register your first device above.</td></tr>';
        knownIds = new Set(devices.map((device) => device.device_id));
      } catch (error) {
        toast(error.message, 'error');
      }
    }

    body.addEventListener('click', async (event) => {
      const button = event.target.closest('[data-toggle]');
      if (!button) return;
      button.disabled = true;
      try {
        const result = await api(`/api/devices/${encodeURIComponent(button.dataset.toggle)}/toggle`, { method: 'POST' });
        toast(result.message, result.enabled ? 'success' : 'info');
        await load();
      } catch (error) {
        toast(error.message, 'error');
        button.disabled = false;
      }
    });

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const payload = Object.fromEntries(new FormData(form).entries());
      if (!payload.device_id.trim() || !payload.device_name.trim() || !payload.device_type.trim()) {
        toast('Please enter all required fields.', 'error');
        return;
      }
      const button = $('#addDeviceBtn');
      button.disabled = true;
      try {
        const result = await api('/api/devices', { method: 'POST', body: payload });
        toast('Device registered successfully.', 'success', 'Secret key generated securely.');
        form.reset();
        await load();
      } catch (error) {
        toast(error.message, 'error');
      } finally {
        button.disabled = false;
      }
    });

    poll(load, 6000);
  }

  /* ---------- 5. authenticate ---------- */
  function initAuthenticate() {
    const select = $('#deviceSelect');
    const challengeBox = $('#challengeBox');
    const hmacInput = $('#hmacInput');
    const ttlLabel = $('#ttl');
    const traceBox = $('#trace');
    const state = { challenge: null, expiresAt: 0, busy: false, lastSuccess: null };

    function trace(kind, who, text) {
      if (traceBox.querySelector('.muted') && traceBox.children.length === 1 && !traceBox.dataset.started) {
        traceBox.innerHTML = '';
        traceBox.dataset.started = '1';
      }
      const line = document.createElement('div');
      line.className = 'line';
      line.innerHTML = `<span class="t">${new Date().toLocaleTimeString([], { hour12: false })}</span><span class="${kind}">${escapeHtml(who)}</span> ${escapeHtml(text)}`;
      traceBox.appendChild(line);
      traceBox.scrollTop = traceBox.scrollHeight;
    }

    /** Stage: 1 = pick device, 2 = need challenge, 3 = need HMAC, 4 = ready to verify. */
    function render() {
      const hasDevice = Boolean(select.value);
      const hasChallenge = Boolean(state.challenge);
      const hasHmac = hasChallenge && hmacInput.value.trim().length > 0;
      const stage = !hasDevice ? 1 : !hasChallenge ? 2 : !hasHmac ? 3 : 4;
      [1, 2, 3, 4].forEach((n) => {
        const step = $(`#step${n}`);
        step.classList.toggle('done', n < stage);
        step.classList.toggle('active', n === stage);
        step.classList.toggle('locked', n > stage);
      });
      $('#btnChallenge').disabled = !hasDevice || state.busy;
      $('#btnHmac').disabled = !hasChallenge || state.busy;
      $('#btnForge').disabled = !hasChallenge || state.busy;
      $('#btnAuth').disabled = stage < 4 || state.busy;
      $('#btnReplay').disabled = !state.lastSuccess || state.busy;
      challengeBox.classList.toggle('placeholder', !hasChallenge);
      challengeBox.textContent = state.challenge || '— not generated yet —';
    }

    function resetChallenge() {
      state.challenge = null;
      state.expiresAt = 0;
      hmacInput.value = '';
      ttlLabel.textContent = '';
      render();
    }

    setInterval(() => {
      if (!state.challenge) return;
      const remaining = Math.ceil((state.expiresAt - Date.now()) / 1000);
      if (remaining <= 0) {
        trace('muted', 'server', 'challenge expired (not answered in time)');
        toast('Challenge expired. Generate a new one.', 'info');
        resetChallenge();
        return;
      }
      ttlLabel.textContent = `expires in ${remaining}s`;
      ttlLabel.classList.toggle('low', remaining <= 20);
    }, 500);

    async function loadDevices() {
      try {
        const { devices } = await api('/api/devices');
        const wanted = new URLSearchParams(window.location.search).get('device')?.toUpperCase();
        select.innerHTML = '<option value="">— choose a device —</option>' + devices.map((device) =>
          `<option value="${escapeHtml(device.device_id)}" ${device.enabled ? '' : 'disabled'}>${escapeHtml(device.device_id)} · ${escapeHtml(device.device_name)}${device.enabled ? '' : ' (disabled)'}</option>`).join('');
        if (wanted && devices.some((device) => device.device_id === wanted && device.enabled)) select.value = wanted;
        render();
      } catch (error) {
        toast(error.message, 'error');
      }
    }

    select.addEventListener('change', () => { resetChallenge(); });

    $('#btnChallenge').addEventListener('click', async () => {
      state.busy = true; render();
      try {
        resetChallenge();
        trace('dev', 'device →', `authentication request: "I am ${select.value}"`);
        const data = await api('/api/device/challenge', { method: 'POST', body: { device_id: select.value } });
        state.challenge = data.challenge;
        state.expiresAt = Date.now() + data.expires_in * 1000;
        trace('srv', 'server →', `random challenge ${data.challenge}`);
        trace('muted', '', `(valid once, for ${data.expires_in} seconds)`);
      } catch (error) {
        trace('evil', 'server', error.message);
        toast(error.message, 'error');
      } finally {
        state.busy = false; render();
      }
    });

    $('#btnHmac').addEventListener('click', async () => {
      state.busy = true; render();
      try {
        const data = await api('/api/simulate/hmac', { method: 'POST', body: { device_id: select.value, challenge: state.challenge } });
        hmacInput.value = data.hmac;
        trace('dev', 'device', 'computes HMAC-SHA256(secret key, challenge)');
        trace('dev', 'device →', `response HMAC ${data.hmac}`);
      } catch (error) {
        toast(error.message, 'error');
        trace('evil', 'error', error.message);
        if (/expired|invalid/i.test(error.message)) resetChallenge();
      } finally {
        state.busy = false; render();
      }
    });

    hmacInput.addEventListener('input', render);

    $('#btnForge').addEventListener('click', () => {
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      hmacInput.value = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
      trace('evil', 'attacker →', `forged HMAC ${hmacInput.value} (attacker does not know the key)`);
      render();
    });

    function progress(percent) {
      const bar = $('#progress');
      bar.classList.toggle('show', percent > 0);
      $('div', bar).style.width = `${percent}%`;
    }

    /** Send one verification request and show the modal. */
    async function verify(payload, { replay = false } = {}) {
      state.busy = true; render();
      progress(15);
      trace(replay ? 'evil' : 'dev', replay ? 'attacker →' : 'device →', `${replay ? 'REPLAYS old ' : ''}HMAC for challenge ${payload.challenge.slice(0, 12)}…`);
      await sleep(350); progress(45);
      let outcome;
      try {
        const [data] = await Promise.all([
          api('/api/device/verify', { method: 'POST', body: payload }),
          sleep(650).then(() => progress(80)),
        ]);
        outcome = { ok: true, data };
      } catch (error) {
        outcome = error.data && error.data.success === false
          ? { ok: false, data: error.data }
          : { ok: false, data: null, error };
      }
      progress(100);
      await sleep(200);
      progress(0);
      state.busy = false;

      if (!outcome.data) {
        toast(outcome.error.message, 'error');
        render();
        return;
      }
      if (outcome.ok) {
        trace('good', 'server', 'recomputed HMAC matches → ACCESS GRANTED');
        state.lastSuccess = { device_id: payload.device_id, challenge: payload.challenge, hmac: payload.hmac };
      } else {
        trace('evil', 'server', `${outcome.data.reason} → ACCESS DENIED`);
      }
      if (replay) render(); else resetChallenge();   // a replay must not discard the live challenge
      showResult(outcome.ok, outcome.data);
    }

    function showResult(ok, data) {
      const mark = ok ? '<path class="ri-mark" d="M30 52 L44 66 L71 36"/>' : '<path class="ri-mark" d="M35 35 L65 65 M65 35 L35 65"/>';
      const lines = ok
        ? `<div><b>Device:</b> ${escapeHtml(data.device_id)}</div>
           <div><b>Challenge:</b> <span class="ok">${escapeHtml(data.challenge)}</span></div>
           <div><b>HMAC:</b> <span class="ok">${escapeHtml(data.hmac)}</span></div>
           <div><b>Access:</b> <span class="ok">${escapeHtml(data.access)}</span></div>`
        : `<div><b>Device:</b> ${escapeHtml(data.device_id)}</div>
           <div><b>Challenge:</b> <span class="${data.challenge === 'Verified' ? 'ok' : 'bad'}">${escapeHtml(data.challenge)}</span></div>
           <div><b>HMAC:</b> <span class="bad">${escapeHtml(data.hmac)}</span></div>
           <div><b>Access:</b> <span class="bad">${escapeHtml(data.access)}</span></div>
           <div><b>Reason:</b> ${escapeHtml(data.reason)}</div>`;
      showModal(`
        <div class="modal ${ok ? 'success' : 'failed'}">
          <div class="result-icon"><svg viewBox="0 0 100 100"><circle class="ri-ring" cx="50" cy="50" r="44"/>${mark}</svg></div>
          <h2>${ok ? 'AUTHENTICATION SUCCESSFUL' : 'AUTHENTICATION FAILED'}</h2>
          <div class="result-lines">${lines}</div>
          <div class="modal-actions">
            <a class="btn" href="/logs">${icon('list')}View Security Logs</a>
            <button class="btn btn-primary" data-close>Close</button>
          </div>
        </div>`);
      toast(ok ? 'Authentication successful. Access granted.' : 'Authentication failed. Access denied.', ok ? 'success' : 'error');
    }

    $('#btnAuth').addEventListener('click', () => {
      verify({ device_id: select.value, challenge: state.challenge, hmac: hmacInput.value.trim() });
    });
    $('#btnReplay').addEventListener('click', () => {
      if (state.lastSuccess) verify({ ...state.lastSuccess }, { replay: true });
    });
    $('#btnClearTrace').addEventListener('click', () => {
      traceBox.innerHTML = '';
      traceBox.dataset.started = '1';
    });

    loadDevices();
  }

  /* ---------- 6. security logs ---------- */
  function initLogs() {
    const body = $('#logsBody');
    const filters = { result: 'all', device: '' };

    async function loadDeviceFilter() {
      try {
        const { devices } = await api('/api/devices');
        $('#deviceFilter').insertAdjacentHTML('beforeend', devices.map((device) =>
          `<option value="${escapeHtml(device.device_id)}">${escapeHtml(device.device_id)}</option>`).join(''));
      } catch (error) { toast(error.message, 'error'); }
    }

    async function load() {
      try {
        const query = new URLSearchParams({ result: filters.result, device: filters.device });
        const { logs } = await api(`/api/logs?${query}`);
        $('#logCount').textContent = `${logs.length} record${logs.length === 1 ? '' : 's'}`;
        body.innerHTML = logs.length ? logs.map((log) => `
          <tr>
            <td>${fmtTime(log.timestamp)}<span class="sub">${fmtDate(log.timestamp)}</span></td>
            <td><span class="dev-id">${escapeHtml(log.device_id)}</span></td>
            <td class="chal" title="${escapeHtml(log.challenge)}">${escapeHtml(log.challenge.slice(0, 16))}…</td>
            <td>${resultBadge(log.result)}</td>
            <td>${escapeHtml(log.method)}</td>
            <td class="card-sub">${escapeHtml(log.reason || '')}${demoBadge(log.is_demo)}</td>
          </tr>`).join('') : '<tr><td colspan="6" class="empty">No authentication attempts match these filters.</td></tr>';
      } catch (error) { toast(error.message, 'error'); }
    }

    $('#resultFilter').addEventListener('click', (event) => {
      const button = event.target.closest('button');
      if (!button) return;
      $$('#resultFilter button').forEach((item) => item.classList.toggle('active', item === button));
      filters.result = button.dataset.value;
      load();
    });
    $('#deviceFilter').addEventListener('change', (event) => { filters.device = event.target.value; load(); });

    $('#btnClearLogs').addEventListener('click', async () => {
      const confirmed = await confirmDialog({
        title: 'Clear all security logs?',
        message: 'This permanently deletes every authentication record. This cannot be undone.',
        confirmText: 'Yes, clear logs',
      });
      if (!confirmed) return;
      try {
        const result = await api('/api/logs', { method: 'DELETE' });
        toast(result.message, 'success');
        load();
      } catch (error) { toast(error.message, 'error'); }
    });

    loadDeviceFilter();
    poll(load, 5000);
  }

  /* ---------- 7. device details ---------- */
  function initDeviceDetails() {
    const deviceId = document.body.dataset.deviceId;
    let enabled = true;

    async function load() {
      try {
        const data = await api(`/api/devices/${encodeURIComponent(deviceId)}`);
        const device = data.device;
        enabled = device.enabled;
        $('#infoBox').innerHTML = `
          <div class="k">Device ID</div><div class="v mono">${escapeHtml(device.device_id)}${demoBadge(device.is_demo)}</div>
          <div class="k">Device Name</div><div class="v">${escapeHtml(device.device_name)}</div>
          <div class="k">Device Type</div><div class="v">${escapeHtml(device.device_type)}</div>
          <div class="k">Registration Date</div><div class="v">${fmtDateTime(device.created_at)}</div>
          <div class="k">Current Status</div><div class="v">${statusBadge(device.status)}</div>
          <div class="k">Firmware</div><div class="v">${fwVersion(device.firmware_version)}<span class="sub"><a href="/firmware">Manage updates →</a></span></div>
          <div class="k">Last Authentication</div><div class="v">${fmtDateTime(device.last_authenticated)}<span class="sub">${timeAgo(device.last_authenticated)}</span></div>`;
        $('#attemptSummary').innerHTML = `<span class="ok">${data.success}</span> / <span class="bad">${data.failed}</span>`;
        const badge = $('#secureBadge');
        badge.textContent = enabled ? 'SECURE' : 'DISABLED';
        badge.className = `badge ${enabled ? 'badge-secure' : 'badge-failed'}`;
        $('#btnToggle span').textContent = enabled ? 'Disable' : 'Enable';
        $('#recentBody').innerHTML = data.recent.length ? data.recent.map((log) => `
          <tr>
            <td>${fmtTime(log.timestamp)}<span class="sub">${fmtDate(log.timestamp)}</span></td>
            <td class="chal" title="${escapeHtml(log.challenge)}">${escapeHtml(log.challenge.slice(0, 16))}…</td>
            <td>${resultBadge(log.result)}</td>
            <td class="card-sub">${escapeHtml(log.reason || '')}${demoBadge(log.is_demo)}</td>
          </tr>`).join('') : '<tr><td colspan="4" class="empty">No authentication attempts yet.</td></tr>';
      } catch (error) { toast(error.message, 'error'); }
    }

    $('#btnToggle').addEventListener('click', async () => {
      try {
        const result = await api(`/api/devices/${encodeURIComponent(deviceId)}/toggle`, { method: 'POST' });
        toast(result.message, result.enabled ? 'success' : 'info');
        load();
      } catch (error) { toast(error.message, 'error'); }
    });

    poll(load, 5000);
  }

  /* ---------- 8. about: animated protocol flow ---------- */
  function initAbout() {
    const steps = $$('#flow .flow-step');
    let index = 0;
    const tick = () => {
      steps.forEach((step, position) => step.classList.toggle('active', position === index));
      index = (index + 1) % steps.length;
    };
    tick();
    setInterval(tick, 1200);
  }

  /* ---------- 9. firmware: publish, fleet, update simulator ---------- */
  function initFirmware() {
    const traceBox = $('#fwTrace');
    const deviceSelect = $('#simDevice');
    const versionSelect = $('#simVersion');
    const form = $('#publishForm');
    let busy = false;

    function trace(kind, who, text) {
      if (!traceBox.dataset.started) {
        traceBox.innerHTML = '';
        traceBox.dataset.started = '1';
      }
      const line = document.createElement('div');
      line.className = 'line';
      line.innerHTML = `<span class="t">${new Date().toLocaleTimeString([], { hour12: false })}</span><span class="${kind}">${escapeHtml(who)}</span> ${escapeHtml(text)}`;
      traceBox.appendChild(line);
      traceBox.scrollTop = traceBox.scrollHeight;
    }

    /** Refill a <select> but keep what the user had chosen, if it still exists. */
    function fillSelect(select, options) {
      const previous = select.value;
      select.innerHTML = options.join('');
      if ([...select.options].some((option) => option.value === previous && !option.disabled)) select.value = previous;
    }

    async function load() {
      try {
        const data = await api('/api/firmware');
        const counts = { up_to_date: 0, outdated: 0, unknown: 0 };
        data.devices.forEach((device) => { counts[device.firmware_status] += 1; });
        $('#fwLatest').textContent = data.latest ? `v${data.latest}` : '—';
        animateNumber($('#fwUpToDate'), counts.up_to_date);
        animateNumber($('#fwOutdated'), counts.outdated);
        animateNumber($('#fwRejected'), data.events.filter((event) => event.result === 'REJECTED').length);
        $('#fwPublicKey').textContent = data.public_key;
        $('#fwFingerprint').textContent = data.fingerprint;
        $('#publishHint').textContent = `The server hashes the image with SHA-256 and signs (version, hash) with its private key. Max ${Math.round(data.max_bytes / 1048576)} MB.`;

        $('#fleetSummary').textContent = `${counts.up_to_date} of ${data.devices.length} on the latest release`;
        $('#fleetBody').innerHTML = data.devices.length ? data.devices.map((device) => `
          <tr>
            <td><a class="dev-id" href="/devices/${encodeURIComponent(device.device_id)}">${escapeHtml(device.device_id)}</a>
                <span class="sub">${escapeHtml(device.device_name)}${device.enabled ? '' : ' · disabled'}</span></td>
            <td>${fwVersion(device.firmware_version)}</td>
            <td>${FIRMWARE_STATUS[device.firmware_status]}</td>
          </tr>`).join('') : '<tr><td colspan="3" class="empty">No devices registered yet.</td></tr>';

        $('#releasesBody').innerHTML = data.releases.length ? data.releases.map((release) => `
          <tr>
            <td>${fwVersion(release.version)}${release.is_latest ? ' <span class="badge badge-success">LATEST</span>' : ''}
                <span class="sub">${escapeHtml(release.notes)}</span></td>
            <td>${escapeHtml(release.filename)}<span class="sub">${release.size.toLocaleString()} bytes</span></td>
            <td class="chal" title="${escapeHtml(release.sha256)}">${escapeHtml(release.sha256.slice(0, 16))}…</td>
            <td class="chal" title="${escapeHtml(release.signature)}">${escapeHtml(release.signature.slice(0, 16))}…</td>
            <td>${fmtDate(release.created_at)}</td>
          </tr>`).join('') : '<tr><td colspan="5" class="empty">No firmware published yet.</td></tr>';

        $('#fwEventsBody').innerHTML = data.events.length ? data.events.map((event) => `
          <tr>
            <td>${fmtTime(event.timestamp)}<span class="sub">${fmtDate(event.timestamp)}</span></td>
            <td><span class="dev-id">${escapeHtml(event.device_id)}</span></td>
            <td>${fwVersion(event.version)}</td>
            <td>${event.result === 'INSTALLED' ? '<span class="badge badge-success">● INSTALLED</span>' : '<span class="badge badge-failed">● REJECTED</span>'}</td>
            <td class="card-sub">${escapeHtml(event.reason || '')}</td>
          </tr>`).join('') : '<tr><td colspan="5" class="empty">No update attempts yet. Try the simulator above.</td></tr>';

        fillSelect(deviceSelect, ['<option value="">— choose a device —</option>', ...data.devices.map((device) =>
          `<option value="${escapeHtml(device.device_id)}" ${device.enabled ? '' : 'disabled'}>${escapeHtml(device.device_id)} · ${device.firmware_version ? `v${escapeHtml(device.firmware_version)}` : 'no version'}${device.enabled ? '' : ' (disabled)'}</option>`)]);
        fillSelect(versionSelect, data.releases.map((release) =>
          `<option value="${escapeHtml(release.version)}">v${escapeHtml(release.version)}${release.is_latest ? ' (latest)' : ''}</option>`));
      } catch (error) { toast(error.message, 'error'); }
    }

    $$('[data-attack]').forEach((button) => button.addEventListener('click', async () => {
      if (busy) return;
      if (!deviceSelect.value) { toast('Choose a device first.', 'info'); return; }
      busy = true;
      $$('[data-attack]').forEach((item) => { item.disabled = true; });
      const attack = button.dataset.attack;
      try {
        trace('muted', '', `— ${button.textContent.trim()} → ${deviceSelect.value} —`);
        const data = await api('/api/simulate/firmware-install', {
          method: 'POST', body: { device_id: deviceSelect.value, version: versionSelect.value, attack },
        });
        for (const step of data.steps) {
          trace(step.kind, step.who, step.text);
          await sleep(320);
        }
        if (data.success) toast(`${data.device_id} updated to v${data.version}.`, 'success', 'Signature verified on the device.');
        else toast('Update refused by the device.', attack === 'none' ? 'error' : 'success', data.reason);
      } catch (error) {
        trace('evil', 'error', error.message);
        toast(error.message, 'error');
      } finally {
        busy = false;
        $$('[data-attack]').forEach((item) => { item.disabled = false; });
        load();
      }
    }));

    $('#btnClearFwTrace').addEventListener('click', () => {
      traceBox.innerHTML = '';
      traceBox.dataset.started = '1';
    });

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const file = $('#fwFile').files[0];
      const version = $('#fwVersion').value.trim();
      if (!file || !version) { toast('Please choose a firmware file and enter a version.', 'error'); return; }
      const button = $('#publishBtn');
      button.disabled = true;
      try {
        const response = await fetch('/api/firmware', {
          method: 'POST', credentials: 'same-origin', body: new FormData(form),
          headers: { Accept: 'application/json', 'X-CSRF-Token': CSRF },
        });
        if (response.status === 401) { window.location.href = '/login'; return; }
        let data = {};
        try { data = await response.json(); } catch (parseError) { /* keep empty */ }
        if (!response.ok) throw new Error(data.error || 'Could not publish the firmware.');
        toast(data.message, 'success', `SHA-256 ${data.sha256.slice(0, 16)}…`);
        trace('srv', 'server', `signed v${data.version}: Ed25519(${data.sha256.slice(0, 16)}…) = ${data.signature.slice(0, 16)}…`);
        form.reset();
        await load();
      } catch (error) {
        toast(error.message === 'Failed to fetch' ? 'Cannot reach the server. Is IoTShield still running?' : error.message, 'error');
      } finally {
        button.disabled = false;
      }
    });

    poll(load, 6000);
  }


  /* ---------- 9. key custody (Shamir shares, seal / unseal) ---------- */
  function initCustody() {
    const WORDS = {
      normal: ['Stored in a file', 'badge-warn', 'The key sits in instance/master.key. Whoever steals that file and the database can read every device key.'],
      sealed: ['Sealed', 'badge-secure', 'The key file is gone and the key is not in memory. Devices cannot authenticate until enough shares are entered.'],
      unsealed: ['Unsealed (in memory only)', 'badge-warn', 'The key was rebuilt from shares and exists only in the server\'s memory. A restart will seal it again.'],
      environment: ['From an environment variable', 'badge-muted', 'The key is supplied through IOTSHIELD_MASTER_KEY, so there is no key file to remove (sealing is not available).'],
    };
    let shown = [];

    const countShares = (text) => (text.match(/IOTS1-[0-9A-Za-z-]+/gi) || []).length;

    async function load() {
      try {
        const data = await api('/api/custody');
        const [label, badge, text] = WORDS[data.state] || [data.state, 'badge-muted', ''];
        $('#kcBadge').innerHTML = `<span class="badge ${badge}">${escapeHtml(label)}</span>`;
        $('#kcStatusText').textContent = text;
        $('#kcFingerprint').textContent = data.fingerprint || '–';
        $('#kcShares').textContent = data.shares
          ? `${data.shares.threshold} of ${data.shares.total} needed · created ${fmtDate(data.shares.issued_at)}`
          : 'None yet. Create shares below.';
        $('#cardUnseal').hidden = !data.sealed;
        $('#kcRotation').textContent = data.rotations
          ? `${data.rotations} time${data.rotations === 1 ? '' : 's'} · last ${fmtDate(data.rotated_at)}`
          : 'Never';
        $('#cardRotate').hidden = !data.can_rotate;
        $('#cardSplit').hidden = !data.can_split;
        $('#cardSeal').hidden = !data.can_seal;
        $('#cardRestore').hidden = !data.can_restore_file;
        $('#splitTotal').max = $('#splitThreshold').max = $('#rotateTotal').max = $('#rotateThreshold').max = data.max_shares;
      } catch (error) { toast(error.message, 'error'); }
    }

    function showShares(data) {
      shown = data.shares;
      $('#shareList').innerHTML = shown.map((share, i) => `
        <div class="share">
          <div class="share-head"><b>Share ${i + 1} of ${data.total}</b>
            <button class="btn btn-sm" type="button" data-copy="${i}">${icon('copy')}Copy</button></div>
          <code class="mono">${escapeHtml(share)}</code>
        </div>`).join('');
      $('#sharesOut').hidden = false;
    }

    function hideShares() {
      shown = [];
      $('#shareList').innerHTML = '';
      $('#sharesOut').hidden = true;
    }

    $('#shareList').addEventListener('click', async (event) => {
      const button = event.target.closest('[data-copy]');
      if (!button) return;
      try {
        await navigator.clipboard.writeText(shown[Number(button.dataset.copy)]);
        toast('Share copied.', 'success', 'Paste it somewhere safe, then hand it to its keeper.');
      } catch (error) { toast('Could not copy. Select the text and copy it by hand.', 'error'); }
    });
    $('#btnHideShares').addEventListener('click', hideShares);

    /** Run a form's request with its button disabled, show a toast, refresh the status. */
    async function submit(form, url, body, { onDone } = {}) {
      const buttons = $$('button', form);
      buttons.forEach((button) => { button.disabled = true; });
      try {
        const data = await api(url, { method: 'POST', body });
        if (onDone) onDone(data);
        await load();
      } catch (error) { toast(error.message, 'error'); }
      finally { buttons.forEach((button) => { button.disabled = false; }); }
    }

    $('#splitForm').addEventListener('submit', (event) => {
      event.preventDefault();
      submit(event.target, '/api/custody/split', {
        total: Number($('#splitTotal').value), threshold: Number($('#splitThreshold').value), password: $('#splitPassword').value,
      }, { onDone: (data) => {
        $('#splitPassword').value = '';
        showShares(data);
        toast(`${data.total} shares created.`, 'success', `Any ${data.threshold} rebuild the key. Copy them now.`);
      } });
    });

    $('#rotateForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!await confirmDialog({
        title: 'Rotate the master key?',
        message: 'A new master key will replace the old one and every device key will be re-encrypted. The old shares will stop working. New shares are shown once, so be ready to copy them.',
        confirmText: 'Yes, rotate',
      })) return;
      submit(event.target, '/api/custody/rotate', {
        total: Number($('#rotateTotal').value), threshold: Number($('#rotateThreshold').value),
        password: $('#rotatePassword').value, backup: $('#rotateBackup').checked,
      }, { onDone: (data) => {
        $('#rotatePassword').value = '';
        showShares(data);
        const box = $('#rotateResult');
        box.hidden = false;
        box.innerHTML = `<b>✓ Key rotated</b><span>${data.devices} device key${data.devices === 1 ? '' : 's'} re-encrypted. `
          + `Key fingerprint ${escapeHtml(data.old_fingerprint)} → ${escapeHtml(data.fingerprint)}. `
          + `The old shares now open nothing.${data.backup ? ` Safety copy of the database: instance/backups/${escapeHtml(data.backup)}.` : ''}</span>`;
        toast('Master key rotated.', 'success', `${data.devices} device keys re-encrypted. Copy the new shares now.`);
        $('#sharesOut').scrollIntoView({ behavior: 'smooth', block: 'center' });
      } });
    });

    $('#testShares').addEventListener('input', () => {
      const found = countShares($('#testShares').value);
      $('#testCount').textContent = found ? `${found} share${found === 1 ? '' : 's'} found` : '';
    });
    $('#testForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const box = $('#testResult');
      try {
        const data = await api('/api/custody/verify', { method: 'POST', body: { shares: $('#testShares').value } });
        box.hidden = false;
        box.className = `result-box ${data.match ? 'good' : 'bad'}`;
        box.innerHTML = `<b>${data.match ? '✓ Match' : '✕ No match'}</b><span>${escapeHtml(data.message)}</span>`;
      } catch (error) { box.hidden = true; toast(error.message, 'error'); }
    });

    $('#sealForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!await confirmDialog({
        title: 'Seal the vault?',
        message: 'The key file will be deleted from the disk. From now on the server needs enough shares to start. Make sure the shares are stored safely.',
        confirmText: 'Yes, seal it',
      })) return;
      submit(event.target, '/api/custody/seal', {
        shares: $('#sealShares').value, password: $('#sealPassword').value, confirm: $('#sealConfirm').value,
      }, { onDone: (data) => {
        ['#sealShares', '#sealPassword', '#sealConfirm'].forEach((selector) => { $(selector).value = ''; });
        hideShares();
        toast(data.message, 'success');
      } });
    });

    $('#unsealForm').addEventListener('submit', (event) => {
      event.preventDefault();
      submit(event.target, '/api/custody/unseal', { shares: $('#unsealShares').value }, { onDone: (data) => {
        $('#unsealShares').value = '';
        toast(data.message, 'success');
      } });
    });

    $('#restoreForm').addEventListener('submit', (event) => {
      event.preventDefault();
      submit(event.target, '/api/custody/restore-file', { password: $('#restorePassword').value }, { onDone: (data) => {
        $('#restorePassword').value = '';
        toast(data.message, 'success');
      } });
    });

    load();
  }

  const pages = {
    dashboard: initDashboard, devices: initDevices, authenticate: initAuthenticate,
    logs: initLogs, about: initAbout, firmware: initFirmware, custody: initCustody,
  };
  const page = document.body.dataset.page;
  if (document.body.dataset.deviceId) initDeviceDetails();
  else if (pages[page]) pages[page]();
})();
