/* kql-qassist.js
   M365 Defender Advanced Hunting KQL Query Assistant
   Loads a draggable modal, takes KVPs, substitutes {{key}} placeholders in a selected template,
   encodes (null byte after each char -> gzip -> base64), and navigates to Advanced Hunting URL.
*/
(() => {
  'use strict';

  const ID = '__kql_qassist__';
  const ROOT_URL = 'https://security.microsoft.com/v2/advanced-hunting';

  // Prevent duplicate instances
  if (document.getElementById(ID)) return;

  // 1) Define your query library here
  const QUERY_LIBRARY = [
    {
      id: 'device_events_by_device',
      name: 'Device events (by device)',
      requiredKeys: ['device'],
      template: [
        'DeviceEvents',
        '| where DeviceName == "{{device}}"',
        '| order by Timestamp desc',
        '| take 200',
      ].join('\n'),
    },
    {
      id: 'network_events_by_ip',
      name: 'Network events (by remote IP)',
      requiredKeys: ['ip'],
      template: [
        'DeviceNetworkEvents',
        '| where RemoteIP == "{{ip}}"',
        '| order by Timestamp desc',
        '| take 200',
      ].join('\n'),
    },
    {
      id: 'file_events_by_sha256',
      name: 'File events (by SHA256)',
      requiredKeys: ['sha256'],
      template: [
        'DeviceFileEvents',
        '| where SHA256 == "{{sha256}}"',
        '| order by Timestamp desc',
        '| take 200',
      ].join('\n'),
    },
  ];

  const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }[c]));

  const clamp = (n, min, max) => Math.min(max, Math.max(min, n));

  const parseKVP = (text) => {
    const out = {};
    const lines = String(text || '').split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i].trim();
      if (!raw) continue;
      const eq = raw.indexOf('=');
      if (eq < 0) throw new Error(`Line ${i + 1}: missing '=' (expected key=value)`);
      const key = raw.slice(0, eq).trim();
      const val = raw.slice(eq + 1);
      if (!key) throw new Error(`Line ${i + 1}: empty key`);
      out[key] = val;
    }
    return out;
  };

  const substitute = (template, kvp) =>
    String(template).replace(/\{\{\s*([a-zA-Z0-9_\-\.]+)\s*\}\}/g, (m, k) =>
      Object.prototype.hasOwnProperty.call(kvp, k) ? String(kvp[k]) : m
    );

  // Null byte after each character (per JS UTF-16 code unit; low byte kept)
  const nullPadBytes = (str) => {
    const s = String(str);
    const bytes = new Uint8Array(s.length * 2);
    for (let i = 0; i < s.length; i++) {
      const code = s.charCodeAt(i);
      bytes[i * 2] = code & 0xff;
      bytes[i * 2 + 1] = 0x00;
    }
    return bytes;
  };

  const gzipBytes = async (bytes) => {
    if (!('CompressionStream' in window)) {
      throw new Error('CompressionStream("gzip") not available.');
    }
    const cs = new CompressionStream('gzip');
    const stream = new Blob([bytes]).stream().pipeThrough(cs);
    const ab = await new Response(stream).arrayBuffer();
    return new Uint8Array(ab);
  };

  const base64FromBytes = (bytes) => {
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  };

  const encodeQuery = async (queryText) => {
    const bytes = nullPadBytes(queryText);
    const gz = await gzipBytes(bytes);
    return base64FromBytes(gz);
  };

  const getTid = (kvp) => {
    try {
      const cur = new URL(location.href);
      return cur.searchParams.get('tid') || (kvp && kvp.tid) || '';
    } catch {
      return (kvp && kvp.tid) || '';
    }
  };

  // UI
  const modal = document.createElement('div');
  modal.id = ID;
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-label', 'KQL query assistant');
  modal.style.cssText = [
    'position:fixed',
    'left:24px',
    'top:24px',
    'width:760px',
    'max-width:calc(100vw - 24px*2)',
    'background:#111827',
    'color:#F9FAFB',
    'border:1px solid rgba(255,255,255,0.18)',
    'border-radius:12px',
    'box-shadow:0 18px 60px rgba(0,0,0,0.55)',
    'z-index:2147483647',
    'font:13px/1.35 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial',
    'overflow:hidden',
  ].join(';');

  modal.innerHTML = `
    <div id="${ID}__hdr" style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;background:#0B1220;cursor:move;user-select:none;">
      <div style="display:flex;flex-direction:column;min-width:0;">
        <div style="font-weight:700;letter-spacing:.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">KQL query assistant</div>
        <div style="opacity:.75;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(ROOT_URL)}</div>
      </div>
      <button id="${ID}__x" type="button" title="Close" style="appearance:none;border:0;background:transparent;color:#F9FAFB;font-size:18px;line-height:18px;padding:6px 8px;border-radius:8px;cursor:pointer;">×</button>
    </div>

    <div style="padding:12px;display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div style="display:flex;flex-direction:column;gap:8px;min-width:0;">
        <div style="display:flex;align-items:baseline;justify-content:space-between;gap:10px;">
          <div style="font-weight:700;">Inputs (KVP)</div>
          <div style="opacity:.75;font-size:12px;white-space:nowrap;">Format: <code style="background:rgba(255,255,255,.08);padding:2px 6px;border-radius:6px;">key=value</code></div>
        </div>
        <textarea id="${ID}__kvp" spellcheck="false" style="width:100%;height:190px;resize:vertical;min-height:140px;max-height:55vh;background:#0B1220;color:#F9FAFB;border:1px solid rgba(255,255,255,0.18);border-radius:10px;padding:10px;outline:none;" placeholder="tid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
device=MY-LAPTOP
ip=1.2.3.4
sha256=...
"></textarea>
        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;">
          <button id="${ID}__loadurl" type="button" style="appearance:none;border:1px solid rgba(255,255,255,0.18);background:transparent;color:#F9FAFB;padding:8px 10px;border-radius:10px;cursor:pointer;">Load URL params</button>
          <button id="${ID}__clear" type="button" style="appearance:none;border:1px solid rgba(255,255,255,0.18);background:transparent;color:#F9FAFB;padding:8px 10px;border-radius:10px;cursor:pointer;">Clear</button>
        </div>
      </div>

      <div style="display:flex;flex-direction:column;gap:8px;min-width:0;">
        <div style="display:flex;align-items:baseline;justify-content:space-between;gap:10px;">
          <div style="font-weight:700;">KQL template</div>
          <div id="${ID}__req" style="opacity:.75;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"></div>
        </div>

        <input id="${ID}__filter" type="text" placeholder="Filter templates…" style="width:100%;background:#0B1220;color:#F9FAFB;border:1px solid rgba(255,255,255,0.18);border-radius:10px;padding:8px 10px;outline:none;" />

        <select id="${ID}__sel" size="7" style="width:100%;background:#0B1220;color:#F9FAFB;border:1px solid rgba(255,255,255,0.18);border-radius:10px;padding:8px 10px;outline:none;"></select>

        <div style="font-weight:700;">Preview</div>
        <textarea id="${ID}__preview" spellcheck="false" readonly style="width:100%;height:190px;resize:vertical;min-height:140px;max-height:55vh;background:#0B1220;color:#F9FAFB;border:1px solid rgba(255,255,255,0.18);border-radius:10px;padding:10px;outline:none;opacity:.95;"></textarea>

        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;">
          <button id="${ID}__copy" type="button" style="appearance:none;border:1px solid rgba(255,255,255,0.18);background:transparent;color:#F9FAFB;padding:8px 10px;border-radius:10px;cursor:pointer;">Copy KQL</button>
          <button id="${ID}__go" type="button" style="appearance:none;border:0;background:#2563EB;color:white;padding:8px 12px;border-radius:10px;cursor:pointer;font-weight:700;">Submit → Advanced Hunting</button>
        </div>
      </div>

      <div style="grid-column:1 / -1;display:flex;flex-direction:column;gap:6px;">
        <div id="${ID}__status" style="display:none;color:#A7F3D0;font-size:12px;"></div>
        <div id="${ID}__err" style="display:none;color:#FCA5A5;font-size:12px;"></div>
      </div>
    </div>
  `;

  document.documentElement.appendChild(modal);

  const hdr = modal.querySelector(`#${ID}__hdr`);
  const kvpTA = modal.querySelector(`#${ID}__kvp`);
  const filterIn = modal.querySelector(`#${ID}__filter`);
  const sel = modal.querySelector(`#${ID}__sel`);
  const req = modal.querySelector(`#${ID}__req`);
  const preview = modal.querySelector(`#${ID}__preview`);
  const status = modal.querySelector(`#${ID}__status`);
  const err = modal.querySelector(`#${ID}__err`);
  const btnGo = modal.querySelector(`#${ID}__go`);

  let statusTimer = null;
  const setStatus = (msg) => {
    status.textContent = msg;
    status.style.display = 'block';
    if (statusTimer) clearTimeout(statusTimer);
    statusTimer = setTimeout(() => {
      status.style.display = 'none';
      status.textContent = '';
    }, 1600);
  };
  const setError = (msg) => {
    err.textContent = msg;
    err.style.display = 'block';
  };
  const clearError = () => {
    err.textContent = '';
    err.style.display = 'none';
  };

  // Draggable header
  let drag = null;
  hdr.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;
    if (e.target && e.target.id === `${ID}__x`) return;
    const r = modal.getBoundingClientRect();
    drag = { dx: e.clientX - r.left, dy: e.clientY - r.top };
    hdr.setPointerCapture(e.pointerId);
    e.preventDefault();
  });
  hdr.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const w = modal.offsetWidth;
    const h = modal.offsetHeight;
    const x = clamp(e.clientX - drag.dx, 8, window.innerWidth - w - 8);
    const y = clamp(e.clientY - drag.dy, 8, window.innerHeight - h - 8);
    modal.style.left = `${x}px`;
    modal.style.top = `${y}px`;
  });
  hdr.addEventListener('pointerup', () => { drag = null; });
  hdr.addEventListener('pointercancel', () => { drag = null; });

  const close = () => { modal.remove(); };
  modal.querySelector(`#${ID}__x`).addEventListener('click', close);

  const computeMissing = (q, kvp) => (q.requiredKeys || []).filter((k) => !(k in kvp) || kvp[k] === '');

  const getSelectedQuery = () => QUERY_LIBRARY.find((q) => q.id === sel.value);

  const render = () => {
    clearError();
    let kvp;
    try {
      kvp = parseKVP(kvpTA.value);
    } catch (e) {
      setError(String(e.message || e));
      return;
    }

    const filter = String(filterIn.value || '').toLowerCase();
    const prevSel = sel.value;
    sel.innerHTML = '';

    const list = QUERY_LIBRARY
      .filter((q) => !filter || (q.name || '').toLowerCase().includes(filter) || (q.id || '').toLowerCase().includes(filter))
      .map((q) => ({ q, missing: computeMissing(q, kvp) }));

    for (const { q, missing } of list) {
      const opt = document.createElement('option');
      opt.value = q.id;
      opt.textContent = missing.length ? `${q.name}  (missing: ${missing.join(', ')})` : q.name;
      opt.disabled = missing.length > 0;
      sel.appendChild(opt);
    }

    if (prevSel && Array.from(sel.options).some((o) => o.value === prevSel)) sel.value = prevSel;
    if (!sel.value) {
      const firstEnabled = Array.from(sel.options).find((o) => !o.disabled);
      if (firstEnabled) sel.value = firstEnabled.value;
    }

    const q = getSelectedQuery();
    if (!q) {
      preview.value = '';
      req.textContent = '';
      return;
    }

    const missing = computeMissing(q, kvp);
    req.textContent = (q.requiredKeys && q.requiredKeys.length)
      ? (missing.length ? `required: ${q.requiredKeys.join(', ')} (missing: ${missing.join(', ')})` : `required: ${q.requiredKeys.join(', ')}`)
      : 'required: (none)';

    preview.value = substitute(q.template, kvp);
  };

  modal.querySelector(`#${ID}__clear`).addEventListener('click', () => {
    kvpTA.value = '';
    render();
    kvpTA.focus();
    setStatus('Cleared.');
  });

  modal.querySelector(`#${ID}__loadurl`).addEventListener('click', () => {
    try {
      const u0 = new URL(location.href);
      kvpTA.value = Array.from(u0.searchParams.entries()).map(([k, v]) => `${k}=${v}`).join('\n');
      render();
      kvpTA.focus();
      setStatus('Loaded URL params.');
    } catch (e) {
      setError(String(e.message || e));
    }
  });

  kvpTA.addEventListener('input', render);
  filterIn.addEventListener('input', render);
  sel.addEventListener('change', render);

  modal.querySelector(`#${ID}__copy`).addEventListener('click', async () => {
    clearError();
    try {
      await navigator.clipboard.writeText(preview.value || '');
      setStatus('Copied KQL to clipboard.');
    } catch {
      preview.focus();
      preview.select();
      document.execCommand('copy');
      setStatus('Copied (fallback).');
    }
  });

  const go = async () => {
    clearError();
    const q = getSelectedQuery();
    if (!q) { setError('Select a template first.'); return; }

    let kvp;
    try { kvp = parseKVP(kvpTA.value); }
    catch (e) { setError(String(e.message || e)); return; }

    const missing = computeMissing(q, kvp);
    if (missing.length) { setError(`Missing required keys: ${missing.join(', ')}`); return; }

    const tid = getTid(kvp);
    if (!tid) { setError('Missing tenant id. Provide tid in the current URL (?tid=...) or as a KVP line (tid=...).'); return; }

    const finalQuery = substitute(q.template, kvp);

    btnGo.disabled = true;
    btnGo.style.opacity = '0.8';
    btnGo.textContent = 'Encoding…';

    try {
      const encoded = await encodeQuery(finalQuery);
      const target = new URL(ROOT_URL);
      target.searchParams.set('tid', tid);
      target.searchParams.set('query', encoded);
      target.searchParams.set('timeRangeId', 'month');
      location.href = target.toString();
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      btnGo.disabled = false;
      btnGo.style.opacity = '1';
      btnGo.textContent = 'Submit → Advanced Hunting';
    }
  };

  btnGo.addEventListener('click', go);

  // Shortcuts
  modal.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close();
  });
  kvpTA.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') go();
  });

  // Initial prefill from current URL params (useful for tid)
  try {
    const u1 = new URL(location.href);
    kvpTA.value = Array.from(u1.searchParams.entries()).map(([k, v]) => `${k}=${v}`).join('\n');
  } catch {}

  render();
  kvpTA.focus();
})();