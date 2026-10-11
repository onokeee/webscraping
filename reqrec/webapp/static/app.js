/* reqrec GUI — vanilla JS, no build step, no external resources.
 *
 * Structure:  api()  ->  per-panel modules (Record / Load / Steps / Code / Run)  ->  render functions.
 * Every piece of recorded content is inserted with textContent (never innerHTML): recordings are
 * attacker-controlled data.
 */
(() => {
  'use strict';

  // ------------------------------------------------------------------ basics
  const body = document.body;
  const TOKEN = body.dataset.token;
  const IS_WINDOWS = body.dataset.isWindows === 'true';
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  class ApiError extends Error {
    constructor(message, status, data) { super(message); this.status = status; this.data = data || {}; }
  }

  async function api(path, { method = 'GET', json, form } = {}) {
    const headers = {};
    if (method !== 'GET') headers['X-Reqrec-Token'] = TOKEN;
    let reqBody;
    if (json !== undefined) { headers['Content-Type'] = 'application/json'; reqBody = JSON.stringify(json); }
    else if (form) reqBody = form;
    let resp;
    try {
      resp = await fetch(path, { method, headers, body: reqBody, credentials: 'same-origin', cache: 'no-store' });
    } catch (e) {
      throw new ApiError('GUI のサーバーに接続できません。reqrec gui が終了していないか確認してください。', 0, {});
    }
    const text = await resp.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { error: text.slice(0, 300) || resp.statusText }; }
    if (!resp.ok) throw new ApiError(data.error || `エラー (HTTP ${resp.status})`, resp.status, data);
    return data;
  }

  const statusBar = $('#status-bar');
  const statusText = $('#status-text');
  function setStatus(message, kind = 'info') {
    statusText.textContent = message;
    statusBar.className = 'status-bar ' + kind;
    statusBar.title = message;
  }
  function fail(err, prefix) {
    const msg = (prefix ? prefix + ': ' : '') + (err && err.message ? err.message : String(err));
    setStatus(msg, 'error');
    console.error(err);
  }

  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k === 'html') node.innerHTML = v; // only used with static, trusted markup
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(node.dataset, v);
      else if (v === true) node.setAttribute(k, '');
      else node.setAttribute(k, v);
    }
    for (const c of [].concat(children)) {
      if (c === null || c === undefined) continue;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
  function fmtBytes(n) {
    if (n === null || n === undefined) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }
  function fmtTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    const p = (x) => String(x).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
  function debounce(fn, ms) {
    let timer = null;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
  }
  function splitHosts(text) {
    return (text || '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
  }

  // ------------------------------------------------------------------ navigation
  const panels = {};
  $$('.panel').forEach((p) => { panels[p.id.replace('panel-', '')] = p; });
  function show(name) {
    Object.entries(panels).forEach(([k, p]) => p.classList.toggle('active', k === name));
    $$('.nav-step').forEach((b) => b.classList.toggle('active', b.dataset.panel === name));
    try { localStorage.setItem('reqrec.panel', name); } catch (e) { /* ignore */ }
    window.scrollTo({ top: 0 });
  }
  $$('.nav-step').forEach((b) => b.addEventListener('click', () => show(b.dataset.panel)));
  document.addEventListener('click', (ev) => {
    const link = ev.target.closest('[data-goto]');
    if (link) { ev.preventDefault(); show(link.dataset.goto); }
  });
  function markDone(name, done, badge) {
    const btn = $(`.nav-step[data-panel="${name}"]`);
    if (btn) btn.classList.toggle('done', !!done);
    const b = $(`#badge-${name}`);
    if (b) { if (badge) { b.textContent = badge; b.hidden = false; } else { b.hidden = true; } }
  }

  if (IS_WINDOWS) $$('.win-only').forEach((n) => { n.hidden = false; });

  // ------------------------------------------------------------------ shared state
  const S = {
    recording: null,     // summary from the server
    plan: null,          // last /api/plan payload
    flows: [],
    exclude: new Set(),
    include: new Set(),
    finalFlowId: null,
    code: null,
    secrets: [],
    savedScript: null,
    runPoll: null,
    recPoll: null,
  };

  // ================================================================== 1 記録
  const Record = (() => {
    const btnStart = $('#btn-rec-start');
    const btnStop = $('#btn-rec-stop');
    const indicator = $('#rec-indicator');
    const stateText = $('#rec-state-text');
    const countEl = $('#rec-flow-count');
    const errEl = $('#rec-error');
    const logEl = $('#rec-log');

    function proxyAddressFromForm() {
      let host = ($('#rec-listen').value || '127.0.0.1').trim();
      if (['0.0.0.0', '::', '*', ''].includes(host)) host = '127.0.0.1';
      return `${host}:${$('#rec-port').value || 8080}`;
    }
    function syncHowto() {
      const addr = proxyAddressFromForm();
      $('#howto-proxy').textContent = addr;
      $('#howto-chrome').textContent = `chrome --proxy-server="${addr}" --user-data-dir=%TEMP%\\reqrec-profile`;
    }
    $('#rec-port').addEventListener('input', syncHowto);
    $('#rec-listen').addEventListener('input', syncHowto);
    syncHowto();

    function render(st) {
      const running = !!st.running;
      indicator.classList.toggle('live', running);
      stateText.textContent = running ? '記録中…（ブラウザを操作してください）' : (st.out ? '停止中（記録は保存されました）' : '停止中');
      countEl.textContent = st.flows ?? 0;
      $('#rec-out').textContent = st.out || '—';
      if (st.port) $('#rec-proxy-address').textContent = `${st.listen_host && !['0.0.0.0', '::'].includes(st.listen_host) ? st.listen_host : '127.0.0.1'}:${st.port}`;
      btnStart.disabled = running;
      btnStop.disabled = !running && !st.out;
      const log = [st.stdout_tail, st.stderr_tail].filter(Boolean).join('\n');
      logEl.textContent = log;
      if (st.error) { errEl.textContent = st.error; errEl.hidden = false; } else { errEl.hidden = true; }
      markDone('record', !!st.out && !running, running ? `${st.flows ?? 0} 件` : null);
      if (running && !S.recPoll) startPolling();
      if (!running && S.recPoll) stopPolling();
    }
    async function poll() {
      try { render(await api('/api/record/status')); } catch (e) { /* transient */ }
    }
    function startPolling() { if (!S.recPoll) S.recPoll = setInterval(poll, 1000); }
    function stopPolling() { clearInterval(S.recPoll); S.recPoll = null; }

    btnStart.addEventListener('click', async () => {
      const port = parseInt($('#rec-port').value, 10);
      if (!(port >= 1 && port <= 65535)) { setStatus('ポート番号は 1〜65535 で指定してください', 'error'); return; }
      btnStart.disabled = true;
      setStatus('記録プロキシを起動しています…', 'busy');
      try {
        const res = await api('/api/record/start', { method: 'POST', json: {
          port,
          hosts: splitHosts($('#rec-hosts').value),
          listen_host: ($('#rec-listen').value || '127.0.0.1').trim(),
          set_system_proxy: IS_WINDOWS && $('#rec-sysproxy').checked,
          append: $('#rec-append').checked,
        } });
        $('#rec-instructions').textContent = res.instructions || '';
        $('#rec-proxy-address').textContent = res.proxy_address || '';
        render(res.status || { running: true, flows: 0, out: res.out });
        if (res.status && res.status.error) {
          setStatus('記録プロキシが起動できませんでした: ' + res.status.error, 'error');
        } else {
          setStatus(`記録を開始しました。ブラウザのプロキシを ${res.proxy_address} にしてサイトを操作してください。`, 'ok');
        }
        if (res.system_proxy && res.system_proxy.set) Windows.refresh();
      } catch (e) {
        btnStart.disabled = false;
        fail(e, '記録を開始できません');
      }
    });

    btnStop.addEventListener('click', async () => {
      btnStop.disabled = true;
      setStatus('記録を停止して読み込んでいます…', 'busy');
      try {
        const res = await api('/api/record/stop', { method: 'POST', json: { append: $('#rec-append').checked } });
        stopPolling();
        await poll();
        Load.applySummary(res);
        let msg = `記録を読み込みました: ${res.flows} 件のリクエスト (${res.out})`;
        if (res.excluded_self) msg += `。GUI 自身への通信 ${res.excluded_self} 件は自動的に除外しました`;
        if (res.proxy_error) msg += '。' + res.proxy_error;
        setStatus(msg, 'ok');
        Load.refreshFiles();
        Windows.refresh();
        show('steps');
        Steps.resetOverrides();
        Steps.replan();
      } catch (e) {
        stopPolling();
        await poll();
        fail(e, '記録を停止できません');
        Windows.refresh();
      }
    });

    return { render, poll, startPolling };
  })();

  // ================================================================== Windows
  const Windows = (() => {
    const out = $('#win-output');
    function showOut(text) { out.textContent = text || ''; out.hidden = !text; }
    async function refresh() {
      if (!IS_WINDOWS) return;
      try {
        const st = await api('/api/win/status');
        const p = st.proxy || {};
        $('#win-proxy-status').textContent = p.enabled ? `有効: ${p.server || '(未設定)'}${st.proxy_backup_active ? '（この GUI が設定中。停止時に元へ戻します）' : ''}` : '無効（直接接続）';
        const c = st.cert || {};
        $('#win-cert-status').textContent = c.installed === true ? `登録済み (${c.path || ''})` : c.installed === false ? (c.path ? `未登録 — ${c.path}` : '未登録 — まず一度「記録開始」でプロキシを起動すると証明書が作成されます') : '確認できません (certutil が見つかりません)';
        $('#btn-win-proxy-restore').disabled = !st.proxy_backup_active;
        if (st.error) showOut(st.error);
      } catch (e) { $('#win-proxy-status').textContent = e.message; }
    }
    if (IS_WINDOWS) {
      $('#btn-win-cert').addEventListener('click', async () => {
        setStatus('CA 証明書を登録しています…', 'busy');
        try {
          const res = await api('/api/win/cert/install', { method: 'POST', json: {} });
          showOut(res.output);
          setStatus('CA 証明書を登録しました', 'ok');
        } catch (e) { showOut(e.data && e.data.output); fail(e, '証明書を登録できません'); }
        refresh();
      });
      $('#btn-win-proxy-restore').addEventListener('click', async () => {
        try {
          const res = await api('/api/win/proxy/restore', { method: 'POST', json: {} });
          setStatus(res.restored ? 'システムプロキシを元の設定に戻しました' : (res.message || '変更はありません'), 'ok');
        } catch (e) { fail(e); }
        refresh();
      });
      $('#btn-win-refresh').addEventListener('click', refresh);
    }
    return { refresh };
  })();

  // ================================================================== 2 読み込み
  const Load = (() => {
    const fileInput = $('#file-input');
    const dropzone = $('#dropzone');
    const btnUpload = $('#btn-upload');
    const filesTbody = $('#files-table tbody');
    const btnOpen = $('#btn-open-selected');

    function describeFiles() {
      const files = Array.from(fileInput.files || []);
      $('#file-chosen').textContent = files.length ? files.map((f) => `${f.name} (${fmtBytes(f.size)})`).join(', ') : 'ファイルが選ばれていません';
      btnUpload.disabled = files.length === 0;
    }
    fileInput.addEventListener('change', describeFiles);
    ['dragenter', 'dragover'].forEach((t) => dropzone.addEventListener(t, (e) => { e.preventDefault(); dropzone.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((t) => dropzone.addEventListener(t, (e) => { e.preventDefault(); dropzone.classList.remove('over'); }));
    dropzone.addEventListener('drop', (e) => {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        describeFiles();
      }
    });

    function applySummary(sum) {
      S.recording = sum;
      const loaded = !!(sum && sum.loaded && sum.flows);
      $('#cur-sources').textContent = loaded && sum.sources && sum.sources.length ? sum.sources.join(', ') : '(なし)';
      $('#cur-flows').textContent = loaded ? `${sum.flows} 件` : '0';
      $('#cur-hosts').textContent = loaded && sum.hosts && sum.hosts.length ? sum.hosts.join(', ') : '—';
      $('#btn-goto-steps').disabled = !loaded;
      $('#btn-clear').disabled = !loaded;
      $('#steps-empty').hidden = loaded;
      $('#steps-body').hidden = !loaded;
      markDone('load', loaded, loaded ? `${sum.flows} 件` : null);
      if (!loaded) { Steps.clearTable(); markDone('steps', false, null); }
    }

    async function upload() {
      const files = Array.from(fileInput.files || []);
      if (!files.length) return;
      const form = new FormData();
      files.forEach((f) => form.append('files', f, f.name));
      form.append('append', $('#append-toggle').checked ? 'true' : 'false');
      btnUpload.disabled = true;
      setStatus(`${files.length} 個のファイルを読み込んでいます…`, 'busy');
      try {
        const res = await api('/api/recordings/upload', { method: 'POST', form });
        applySummary(res);
        setStatus(`読み込みました: ${res.flows} 件のリクエスト` + (res.appended ? '（結合済み）' : ''), 'ok');
        fileInput.value = '';
        describeFiles();
        refreshFiles();
        show('steps');
        Steps.resetOverrides();
        Steps.replan();
      } catch (e) {
        btnUpload.disabled = false;
        fail(e, '読み込みに失敗しました');
      }
    }
    btnUpload.addEventListener('click', upload);

    async function refreshFiles() {
      try {
        const res = await api('/api/recordings');
        clear(filesTbody);
        if (!res.files.length) {
          filesTbody.appendChild(el('tr', {}, el('td', { colspan: 6, class: 'empty', text: '作業フォルダに記録ファイルはまだありません' })));
        }
        res.files.forEach((f) => {
          const cb = el('input', { type: 'checkbox', dataset: { folder: f.folder, name: f.name } });
          cb.addEventListener('change', updateOpenButton);
          filesTbody.appendChild(el('tr', {}, [
            el('td', { class: 'col-check' }, cb),
            el('td', { text: f.name }),
            el('td', { text: f.folder === 'recordings' ? 'recordings (この GUI で記録)' : 'uploads (読み込み)' }),
            el('td', { class: 'num', text: f.flows === null || f.flows === undefined ? '—' : String(f.flows) }),
            el('td', { class: 'num', text: fmtBytes(f.size) }),
            el('td', { text: fmtTime(f.mtime) }),
          ]));
        });
        updateOpenButton();
      } catch (e) { fail(e, 'ファイル一覧を取得できません'); }
    }
    function selectedFiles() {
      return $$('input[type=checkbox]:checked', filesTbody).map((cb) => ({ folder: cb.dataset.folder, name: cb.dataset.name }));
    }
    function updateOpenButton() { btnOpen.disabled = selectedFiles().length === 0; }
    btnOpen.addEventListener('click', async () => {
      const names = selectedFiles();
      if (!names.length) return;
      setStatus('ファイルを開いています…', 'busy');
      try {
        const res = await api('/api/recordings/open', { method: 'POST', json: { names, append: $('#append-toggle').checked } });
        applySummary(res);
        let msg = `開きました: ${res.flows} 件のリクエスト`;
        if (res.excluded_self) msg += `（GUI 自身への通信 ${res.excluded_self} 件を自動除外）`;
        setStatus(msg, 'ok');
        show('steps');
        Steps.resetOverrides();
        Steps.replan();
      } catch (e) { fail(e, 'ファイルを開けません'); }
    });
    $('#btn-refresh-files').addEventListener('click', refreshFiles);
    $('#btn-goto-steps').addEventListener('click', () => { show('steps'); if (!S.plan) Steps.replan(); });
    $('#btn-clear').addEventListener('click', async () => {
      try {
        const res = await api('/api/recordings/clear', { method: 'POST', json: {} });
        applySummary(res.recording);
        S.plan = null;
        Steps.resetOverrides();
        setStatus('記録をクリアしました', 'ok');
      } catch (e) { fail(e); }
    });

    return { applySummary, refreshFiles };
  })();

  // ================================================================== 3 ステップ
  const Steps = (() => {
    const tbody = $('#flow-tbody');
    const REASONS = [
      ['excluded by user', '手動で除外'],
      ['static asset', '静的ファイル'],
      ['tracker/analytics host', 'トラッカー / 解析サービス'],
      ['no response recorded', 'レスポンスなし (未完了)'],
      ['CORS preflight', 'CORS プリフライト'],
      ['304 not modified', '304 (ブラウザキャッシュ)'],
      ['websocket', 'WebSocket'],
      ['server-sent events', 'SSE ストリーム'],
      ['host excluded', '除外ホスト'],
      ['host not in', '対象ホスト外'],
      ['auth', '認証ハンドシェイク (統合済み)'],
      ['not used', '使用されず (他ステップに統合 / 上限超過)'],
    ];
    function reasonLabel(reason) {
      if (!reason) return '';
      const hit = REASONS.find(([k]) => reason.toLowerCase().startsWith(k) || reason.toLowerCase().includes(k));
      if (!hit) return reason;
      const m = /\((.*)\)$/.exec(reason);
      return hit[1] + (m && hit[0] === 'static asset' ? ` (${m[1]})` : '');
    }
    function shortMime(mime, rtype) {
      if (!mime) return rtype || '—';
      const map = { 'text/html': 'HTML', 'application/json': 'JSON', 'text/css': 'CSS', 'application/javascript': 'JS', 'text/javascript': 'JS', 'application/x-javascript': 'JS', 'text/plain': 'テキスト', 'text/csv': 'CSV', 'application/pdf': 'PDF', 'application/xml': 'XML', 'text/xml': 'XML', 'application/xhtml+xml': 'XHTML' };
      if (map[mime]) return map[mime];
      if (mime.startsWith('image/')) return '画像';
      if (mime.startsWith('font/')) return 'フォント';
      if (mime.endsWith('+json')) return 'JSON';
      if (mime.endsWith('+xml')) return 'XML';
      return mime.split('/').pop().slice(0, 14);
    }

    function collectPlanOptions() {
      const o = {};
      $$('input.opt[type=checkbox]').forEach((cb) => { o[cb.dataset.opt] = cb.checked; });
      o.include_hosts = splitHosts($('#opt-include-hosts').value);
      if (!o.include_hosts.length) o.include_hosts = null;
      o.exclude_hosts = splitHosts($('#opt-exclude-hosts').value);
      const minLen = parseInt($('#opt-min-len').value, 10);
      if (minLen >= 1) o.min_value_length = minLen;
      const maxSteps = parseInt($('#opt-max-steps').value, 10);
      o.max_steps = maxSteps >= 1 ? maxSteps : null;
      o.exclude_flow_ids = Array.from(S.exclude);
      o.include_flow_ids = Array.from(S.include);
      o.final_flow_id = S.finalFlowId;
      return o;
    }
    function collectGenOptions() {
      const g = {};
      $$('.gopt').forEach((n) => {
        const key = n.dataset.gopt;
        if (n.type === 'checkbox') g[key] = n.checked;
        else if (n.type === 'number') { const v = parseFloat(n.value); if (!Number.isNaN(v)) g[key] = v; }
        else g[key] = n.value;
      });
      return g;
    }

    let inflight = 0;
    async function replan() {
      if (!S.recording || !S.recording.loaded) return;
      const my = ++inflight;
      setStatus('解析しています…', 'busy');
      tbody.classList.add('loading');
      try {
        const res = await api('/api/plan', { method: 'POST', json: { plan_options: collectPlanOptions() } });
        if (my !== inflight) return; // a newer request superseded this one
        S.plan = res;
        S.flows = res.flows || [];
        render(res);
        setStatus(`解析完了: ステップ ${res.steps_kept} 件 / 採用 ${res.flows_kept} 件 / 除外 ${res.dropped} 件`, 'ok');
      } catch (e) {
        if (my === inflight) fail(e, '解析に失敗しました');
      } finally {
        tbody.classList.remove('loading');
      }
    }
    const replanDebounced = debounce(replan, 250);

    function resetOverrides() {
      S.exclude = new Set();
      S.include = new Set();
      S.finalFlowId = null;
    }
    function clearTable() {
      clear(tbody).appendChild(el('tr', {}, el('td', { colspan: 9, class: 'empty', text: '記録が読み込まれていません' })));
    }

    function render(plan) {
      // summary card
      $('#sum-steps').textContent = plan.steps_kept;
      $('#sum-kept').textContent = plan.flows_kept;
      $('#sum-dropped').textContent = plan.dropped;
      $('#sum-vars').textContent = (plan.steps || []).reduce((n, s) => n + (s.extractors || []).length, 0);
      const finalEl = $('#sum-final');
      const finalBtn = $('#btn-final-clear');
      clear(finalEl);
      if (plan.final_step_index) {
        const st = (plan.steps || []).find((s) => s.index === plan.final_step_index);
        finalEl.appendChild(el('span', { text: `ステップ ${plan.final_step_index}${st ? ` (${st.method} ${st.url})` : ''} ` }));
        finalEl.appendChild(finalBtn); finalBtn.hidden = false;
      } else if (S.finalFlowId) {
        finalEl.appendChild(el('span', { class: 'hint', text: `指定した ${S.finalFlowId} は除外されているため、最後のステップを結果にします `}));
        finalEl.appendChild(finalBtn); finalBtn.hidden = false;
      } else {
        finalEl.appendChild(el('span', { text: '最後のステップ (既定) ' }));
        finalEl.appendChild(finalBtn); finalBtn.hidden = true;
      }
      const authEl = clear($('#sum-auth'));
      if (plan.auth) {
        const a = plan.auth;
        const kind = { ntlm: 'NTLM (Windows 統合認証)', negotiate: 'Negotiate / Kerberos (Windows 統合認証)', basic: 'Basic 認証', digest: 'Digest 認証' }[a.kind] || a.kind;
        authEl.appendChild(el('span', { class: 'auth-pill', text: kind }));
        authEl.appendChild(document.createTextNode(` ${(a.hosts || []).join(', ')}${a.username ? ` / 記録時のユーザー: ${a.username}` : ''} — 生成コードでは session.auth で認証します`));
      } else authEl.textContent = '検出されませんでした';
      const constEl = clear($('#sum-constants'));
      if (plan.constants && plan.constants.length) {
        plan.constants.forEach((c, i) => {
          if (i) constEl.appendChild(document.createTextNode(', '));
          constEl.appendChild(el('code', { text: c.name + (c.secret ? ` (秘密: 環境変数 ${c.env_var})` : c.value !== null && c.value !== undefined ? ` = ${String(c.value).slice(0, 40)}` : '') }));
        });
      } else constEl.textContent = 'なし';
      const loopEl = clear($('#sum-loops'));
      if (plan.loops && plan.loops.length) {
        loopEl.textContent = plan.loops.map((l) => `ステップ ${l.step_index}: ${l.var} を ${l.count} 回${l.numeric_range ? ` (${l.numeric_range[0]}〜${l.numeric_range[1]})` : ''}`).join(' / ');
      } else loopEl.textContent = 'なし';
      $('#sum-self').textContent = plan.excluded_self_flows ? `GUI 自身への通信 ${plan.excluded_self_flows} 件を記録から除外済み` : 'なし';
      const warnWrap = $('#sum-warnings-wrap');
      const warnList = clear($('#sum-warnings'));
      (plan.warnings || []).forEach((w) => warnList.appendChild(el('li', { text: w })));
      warnWrap.hidden = !(plan.warnings && plan.warnings.length);
      markDone('steps', plan.steps_kept > 0, `${plan.steps_kept} ステップ`);

      renderTable();
    }

    function renderTable() {
      const filter = ($('#table-filter').value || '').toLowerCase();
      const showDropped = $('#show-dropped').checked;
      clear(tbody);
      let shown = 0;
      S.flows.forEach((f) => {
        if (!showDropped && !f.kept) return;
        if (filter && !(`${f.method} ${f.url} ${f.host} ${f.reason || ''}`.toLowerCase().includes(filter))) return;
        shown++;
        const tr = el('tr', { class: (f.kept ? 'kept' : 'dropped') + (f.is_final ? ' final' : ''), dataset: { flowId: f.id } });
        const cb = el('input', { type: 'checkbox', title: f.kept ? 'チェックを外すとこのリクエストを除外します' : 'チェックを入れるとこのリクエストを採用します' });
        cb.checked = f.kept;
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', () => toggleFlow(f, cb.checked));
        const radio = el('input', { type: 'radio', name: 'final-flow', title: 'このリクエストの結果をスクリプトの出力にします' });
        radio.checked = S.finalFlowId === f.id || (!S.finalFlowId && f.is_final);
        radio.disabled = !f.kept;
        radio.addEventListener('click', (e) => e.stopPropagation());
        radio.addEventListener('change', () => { if (radio.checked) { S.finalFlowId = f.id; replanDebounced(); } });
        let urlNode;
        try {
          const u = new URL(f.url);
          urlNode = el('span', {}, [el('span', { class: 'url-host', text: u.protocol + '//' + u.host }), document.createTextNode(u.pathname + u.search + u.hash)]);
        } catch (e) { urlNode = document.createTextNode(f.url); }
        const statusClass = f.status === null || f.status === undefined ? 's0' : 's' + String(f.status)[0];
        tr.append(
          el('td', { class: 'col-check' }, cb),
          el('td', { class: 'col-radio' }, radio),
          el('td', { class: 'col-step' }, f.step_index ? el('span', { class: 'step-no', text: String(f.step_index) }) : el('span', { class: 'hint', text: f.id })),
          el('td', { class: 'col-method' }, el('span', { class: 'method ' + f.method, text: f.method })),
          el('td', { class: 'col-status' }, el('span', { class: 'status-pill ' + statusClass, text: f.status === null || f.status === undefined ? '—' : String(f.status) })),
          el('td', { class: 'col-type', text: shortMime(f.mime, f.resource_type) }),
          el('td', { class: 'col-url', title: f.url }, urlNode),
          el('td', { class: 'col-ref', title: f.referer || '', text: f.referer ? f.referer.replace(/^https?:\/\//, '') : '' }),
          el('td', { class: 'col-reason' }, el('span', { class: 'reason' + (f.reason === 'excluded by user' ? ' user' : ''), text: f.kept ? (f.is_final ? '採用（結果）' : '採用') : reasonLabel(f.reason) })),
        );
        tr.addEventListener('click', () => Drawer.open(f.id));
        tbody.appendChild(tr);
      });
      if (!shown) tbody.appendChild(el('tr', {}, el('td', { colspan: 9, class: 'empty', text: S.flows.length ? '条件に合う行がありません' : 'リクエストがありません' })));
      $('#table-count').textContent = `(${shown} / ${S.flows.length} 件を表示)`;
    }

    function toggleFlow(flow, checked) {
      if (checked) {
        S.exclude.delete(flow.id);
        if (!flow.kept) S.include.add(flow.id);
      } else {
        S.include.delete(flow.id);
        S.exclude.add(flow.id);
        if (S.finalFlowId === flow.id) S.finalFlowId = null;
      }
      replanDebounced();
    }

    $$('input.opt, .opt-num').forEach((n) => n.addEventListener('change', replanDebounced));
    $$('.opt-text').forEach((n) => n.addEventListener('input', debounce(replan, 600)));
    $('#table-filter').addEventListener('input', debounce(renderTable, 120));
    $('#show-dropped').addEventListener('change', renderTable);
    $('#btn-replan').addEventListener('click', replan);
    $('#btn-final-clear').addEventListener('click', () => { S.finalFlowId = null; replan(); });
    $('#btn-goto-code').addEventListener('click', () => show('code'));

    return { replan, resetOverrides, clearTable, collectPlanOptions, collectGenOptions, render };
  })();

  // ================================================================== 詳細ドロワー
  const Drawer = (() => {
    const drawer = $('#drawer');
    const backdrop = $('#drawer-backdrop');
    function close() { drawer.hidden = true; backdrop.hidden = true; }
    $('#drawer-close').addEventListener('click', close);
    backdrop.addEventListener('click', close);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !drawer.hidden) close(); });
    $$('.tab', drawer).forEach((t) => t.addEventListener('click', () => {
      $$('.tab', drawer).forEach((x) => x.classList.toggle('active', x === t));
      $$('.tab-body', drawer).forEach((b) => b.classList.toggle('active', b.id === 'tab-' + t.dataset.tab));
    }));
    function fillPairs(table, pairs, emptyText) {
      const tb = clear(table.querySelector('tbody'));
      if (!pairs || !pairs.length) { tb.appendChild(el('tr', {}, el('td', { colspan: 2, class: 'empty', text: emptyText }))); return; }
      pairs.forEach(([k, v]) => tb.appendChild(el('tr', {}, [el('td', { text: k }), el('td', { text: v })])));
    }
    function bodyInfo(b) {
      if (!b || b.kind === 'none') return '(なし)';
      const kind = { json: 'JSON', html: 'HTML', form: 'フォーム', text: 'テキスト', binary: 'バイナリ' }[b.kind] || b.kind;
      return `${kind} / ${fmtBytes(b.size)}${b.mime ? ` / ${b.mime}` : ''}${b.truncated ? ' / 先頭 200 KB のみ表示' : ''}`;
    }
    function bodyText(b) {
      if (!b || b.kind === 'none') return '';
      if (b.kind === 'binary') return `(バイナリデータ ${fmtBytes(b.size)} — 表示できません)`;
      return b.text || '';
    }
    async function open(flowId) {
      try {
        const d = await api('/api/flow/' + encodeURIComponent(flowId));
        $('#dr-method').textContent = d.request.method;
        $('#dr-method').className = 'method ' + d.request.method;
        const st = d.response ? d.response.status : null;
        const pill = $('#dr-status');
        pill.textContent = st === null ? 'レスポンスなし' : String(st);
        pill.className = 'status-pill ' + (st === null ? 's0' : 's' + String(st)[0]);
        $('#dr-flow-id').textContent = `${d.id}${d.step_index ? ` / ステップ ${d.step_index}` : d.reason ? ` / 除外: ${d.reason}` : ''}`;
        $('#dr-url').textContent = d.request.url;
        $('#dr-meta').textContent = [d.started_at_iso ? `時刻 ${d.started_at_iso}` : null, d.resource_type ? `種類 ${d.resource_type}` : null, d.page_ref ? `ページ ${d.page_ref}` : null].filter(Boolean).join(' / ');
        fillPairs($('#dr-req-query'), d.request.query, 'クエリパラメータなし');
        fillPairs($('#dr-req-headers'), d.request.headers, 'ヘッダーなし');
        const rb = d.request.body;
        $('#dr-req-body-info').textContent = bodyInfo(rb);
        const formTable = $('#dr-req-form');
        if (rb && rb.kind === 'form' && rb.pairs) { fillPairs(formTable, rb.pairs, ''); formTable.hidden = false; } else formTable.hidden = true;
        $('#dr-req-body').textContent = bodyText(rb);
        if (d.response) {
          fillPairs($('#dr-resp-headers'), d.response.headers, 'ヘッダーなし');
          $('#dr-resp-body-info').textContent = bodyInfo(d.response.body);
          $('#dr-resp-body').textContent = bodyText(d.response.body);
        } else {
          fillPairs($('#dr-resp-headers'), [], 'レスポンスは記録されていません');
          $('#dr-resp-body-info').textContent = '';
          $('#dr-resp-body').textContent = '(レスポンスなし)';
        }
        drawer.hidden = false; backdrop.hidden = false;
      } catch (e) { fail(e, '詳細を取得できません'); }
    }
    return { open, close };
  })();

  // ================================================================== 4 コード
  const Code = (() => {
    const preview = $('#code-preview');
    const btnSave = $('#btn-save');
    const btnDownload = $('#btn-download');
    const nameInput = $('#script-name');

    function renderSecrets(secrets) {
      S.secrets = secrets || [];
      const wrap = $('#gen-secrets-wrap');
      const list = clear($('#gen-secrets'));
      S.secrets.forEach((s) => list.appendChild(el('li', {}, [el('code', { text: s.env_var }), document.createTextNode(` — ${/^[A-Za-z_][A-Za-z0-9_]*$/.test(s.name) ? '定数 ' : ''}${s.name}${s.comment ? ` (${s.comment})` : ''}`)])));
      wrap.hidden = !S.secrets.length;
      Run.renderEnvInputs();
    }

    $('#btn-generate').addEventListener('click', async () => {
      if (!S.recording || !S.recording.loaded) { setStatus('先に記録を読み込んでください', 'error'); show('load'); return; }
      setStatus('スクリプトを生成しています…', 'busy');
      try {
        const res = await api('/api/generate', { method: 'POST', json: { plan_options: Steps.collectPlanOptions(), gen_options: Steps.collectGenOptions() } });
        S.code = res.code;
        preview.textContent = res.code;
        $('#code-lines').textContent = `(${res.code.split('\n').length} 行 / ${res.steps} ステップ)`;
        $('#gen-summary').textContent = res.summary || '';
        $('#gen-summary').hidden = !res.summary;
        const wl = clear($('#gen-warnings'));
        (res.warnings || []).forEach((w) => wl.appendChild(el('li', { text: w })));
        $('#gen-warnings-wrap').hidden = !(res.warnings && res.warnings.length);
        renderSecrets(res.secrets);
        if (!nameInput.value.trim() && res.suggested_name) nameInput.value = res.suggested_name;
        btnSave.disabled = false;
        markDone('code', true, `${res.steps} ステップ`);
        setStatus(`スクリプトを生成しました (${res.steps} ステップ)。ファイル名を確認して [保存] してください。`, 'ok');
      } catch (e) { fail(e, '生成に失敗しました'); }
    });

    btnSave.addEventListener('click', async () => {
      if (!S.code) return;
      let name = nameInput.value.trim();
      if (!name) { setStatus('ファイル名を入力してください', 'error'); nameInput.focus(); return; }
      setStatus('保存しています…', 'busy');
      try {
        const res = await api('/api/scripts/save', { method: 'POST', json: { name, code: S.code } });
        S.savedScript = res.name;
        $('#save-result').textContent = `保存しました: ${res.path}`;
        btnDownload.href = res.download_url;
        btnDownload.setAttribute('download', res.name);
        btnDownload.classList.remove('disabled');
        btnDownload.removeAttribute('aria-disabled');
        $('#btn-goto-run').disabled = false;
        setStatus(`保存しました: ${res.name}`, 'ok');
        await Run.refreshScripts(res.name);
      } catch (e) { fail(e, '保存に失敗しました'); }
    });
    $('#btn-goto-run').addEventListener('click', () => show('run'));

    return { renderSecrets };
  })();

  // ================================================================== 5 実行
  const Run = (() => {
    const select = $('#run-script');
    const envWrap = $('#env-inputs');
    const btnRun = $('#btn-run');
    const btnStop = $('#btn-run-stop');
    const stateEl = $('#run-state');
    const outEl = $('#run-stdout');
    const errEl = $('#run-stderr');

    async function refreshScripts(selectName) {
      try {
        const res = await api('/api/scripts');
        clear(select);
        if (!res.files.length) select.appendChild(el('option', { value: '', text: '(保存されたスクリプトはありません — 「4 コード」で保存してください)' }));
        res.files.forEach((f) => select.appendChild(el('option', { value: f.name, text: `${f.name}  (${fmtBytes(f.size)}, ${fmtTime(f.mtime)})` })));
        const want = selectName || S.savedScript || res.last;
        if (want && res.files.some((f) => f.name === want)) select.value = want;
      } catch (e) { fail(e, 'スクリプト一覧を取得できません'); }
    }
    function renderEnvInputs() {
      clear(envWrap);
      if (!S.secrets.length) {
        envWrap.appendChild(el('p', { class: 'hint', text: '生成したスクリプトに秘密情報がなければ入力は不要です。' }));
        return;
      }
      S.secrets.forEach((s) => {
        const id = 'env-' + s.env_var;
        envWrap.appendChild(el('label', { for: id, text: s.env_var }));
        const isSecret = s.secret !== false;
        envWrap.appendChild(el('div', {}, [
          el('input', { type: isSecret ? 'password' : 'text', id, class: 'env-input w-m', dataset: { env: s.env_var }, autocomplete: 'off', placeholder: s.name, value: !isSecret && s.default ? s.default : undefined }),
          el('div', { class: 'hint', text: `${s.name}${s.comment ? ' — ' + s.comment : ''}（実行プロセスにだけ渡され、保存されません）` }),
        ]));
      });
    }
    function collectEnv() {
      const env = {};
      $$('.env-input', envWrap).forEach((i) => { if (i.value !== '') env[i.dataset.env] = i.value; });
      return env;
    }
    function render(st) {
      const running = !!st.running;
      btnRun.disabled = running;
      btnStop.disabled = !running;
      outEl.textContent = st.stdout_tail || '';
      errEl.textContent = st.stderr_tail || '';
      if (running) { stateEl.textContent = `実行中… (${st.name || ''})`; stateEl.className = 'run-state running'; }
      else if (st.exit_code === null || st.exit_code === undefined) { stateEl.textContent = '待機中'; stateEl.className = 'run-state'; }
      else if (st.exit_code === 0) { stateEl.textContent = `正常終了 (${st.name || ''})`; stateEl.className = 'run-state ok'; }
      else { stateEl.textContent = st.stopped_by_user ? '停止しました' : `エラー終了 (終了コード ${st.exit_code})`; stateEl.className = 'run-state fail'; }
      $('#btn-save-output').disabled = running || !st.started_at;
      if (running) outEl.scrollTop = outEl.scrollHeight;
      markDone('run', !running && st.exit_code === 0, null);
      if (running && !S.runPoll) S.runPoll = setInterval(poll, 1000);
      if (!running && S.runPoll) { clearInterval(S.runPoll); S.runPoll = null; }
    }
    async function poll() {
      try {
        const st = await api('/api/run/status');
        render(st);
        if (!st.running && st.exit_code !== null && st.exit_code !== undefined) {
          setStatus(st.exit_code === 0 ? 'スクリプトは正常に終了しました' : `スクリプトは終了コード ${st.exit_code} で終了しました（標準エラーを確認してください）`, st.exit_code === 0 ? 'ok' : 'error');
        }
      } catch (e) { /* transient */ }
    }
    btnRun.addEventListener('click', async () => {
      const name = select.value;
      if (!name) { setStatus('実行するスクリプトを選んでください（「4 コード」で保存できます）', 'error'); return; }
      btnRun.disabled = true;
      setStatus(`${name} を実行しています…`, 'busy');
      try {
        const st = await api('/api/run', { method: 'POST', json: { name, env: collectEnv() } });
        render(st);
      } catch (e) { btnRun.disabled = false; fail(e, '実行できません'); }
    });
    btnStop.addEventListener('click', async () => {
      try { render(await api('/api/run/stop', { method: 'POST', json: {} })); setStatus('スクリプトを停止しました', 'info'); } catch (e) { fail(e); }
    });
    $('#btn-refresh-scripts').addEventListener('click', () => refreshScripts());
    $('#btn-save-output').addEventListener('click', async () => {
      const name = $('#output-name').value.trim();
      try {
        const res = await api('/api/run/save_output', { method: 'POST', json: name ? { name } : {} });
        $('#save-output-result').textContent = `保存しました: ${res.path} (${fmtBytes(res.size)})${res.truncated ? ' ※出力が大きすぎたため途中までです' : ''}`;
        setStatus(`結果を保存しました: ${res.name}`, 'ok');
      } catch (e) { fail(e, '結果を保存できません'); }
    });
    return { refreshScripts, renderEnvInputs, render };
  })();

  // ================================================================== 起動
  async function init() {
    try {
      const st = await api('/api/state');
      Record.render(st.recorder || {});
      Load.applySummary(st.recording || { loaded: false });
      Run.render(st.run || {});
      if (st.secrets && st.secrets.length) Code.renderSecrets(st.secrets);
      if (st.last_script) S.savedScript = st.last_script;
      if (st.recording && st.recording.loaded) Steps.replan();
      Load.refreshFiles();
      Run.refreshScripts();
      Windows.refresh();
      let panel = null;
      try { panel = localStorage.getItem('reqrec.panel'); } catch (e) { /* ignore */ }
      if (st.recorder && st.recorder.running) panel = 'record';
      else if (!panel && st.recording && st.recording.loaded) panel = 'steps';
      if (panel && panels[panel]) show(panel);
    } catch (e) { fail(e, '初期化に失敗しました'); }
  }
  init();
})();
