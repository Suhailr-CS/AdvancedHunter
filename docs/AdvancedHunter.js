(function () {
  "use strict";

  const DEFAULT_ROOT_URL = "https://security.microsoft.com/v2/advanced-hunting";
  const DEFAULT_ID = "__kql_qassist__";

  const DEFAULT_QUERY_LIBRARY = [
    {
      id: "device_events_by_device",
      name: "Device events (by device)",
      requiredKeys: ["device"],
      template: [
        "DeviceEvents",
        '| where DeviceName == "{{device}}"',
        "| order by Timestamp desc",
        "| take 200",
      ].join("\n"),
    },
    {
      id: "network_events_by_ip",
      name: "Network events (by remote IP)",
      requiredKeys: ["ip"],
      template: [
        "DeviceNetworkEvents",
        '| where RemoteIP == "{{ip}}"',
        "| order by Timestamp desc",
        "| take 200",
      ].join("\n"),
    },
    {
      id: "file_events_by_sha256",
      name: "File events (by SHA256)",
      requiredKeys: ["sha256"],
      template: [
        "DeviceFileEvents",
        '| where SHA256 == "{{sha256}}"',
        "| order by Timestamp desc",
        "| take 200",
      ].join("\n"),
    },
  ];

  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => {
      const m = {
        "&": "&amp;",
        "<​": "&lt;",     // FIXED (removed hidden char)
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      };
      return m[c] || c;
    });
  }

  function clamp(n, min, max) {
    return Math.min(max, Math.max(min, n));
  }

  function parseKVP(text) {
    const out = {};
    const lines = String(text || "").split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i].trim();
      if (!raw) continue;
      const eq = raw.indexOf("=");
      if (eq < 0) throw new Error(`Line ${i + 1}: missing '=' (expected key=value)`);
      const key = raw.slice(0, eq).trim();
      const val = raw.slice(eq + 1);
      if (!key) throw new Error(`Line ${i + 1}: empty key`);
      out[key] = val;
    }
    return out;
  }

  function substitute(template, kvp) {
    return String(template).replace(/\{\{\s*([a-zA-Z0-9_\-\.]+)\s*\}\}/g, (m, k) => {
      if (Object.prototype.hasOwnProperty.call(kvp, k)) return String(kvp[k]);
      return m;
    });
  }

  // FIX: Proper UTF-16LE encoding (2 bytes per code unit).
  // This matches "null byte after each character" ONLY for ASCII,
  // but also correctly preserves non-ASCII characters.
  function utf16leBytes(str) {
    const s = String(str);
    const bytes = new Uint8Array(s.length * 2);
    for (let i = 0; i < s.length; i++) {
      const codeUnit = s.charCodeAt(i);   // 0..65535
      bytes[i * 2] = codeUnit & 0xff;     // low byte
      bytes[i * 2 + 1] = (codeUnit >>> 8) & 0xff; // high byte
    }
    return bytes;
  }

  async function gzipBytes(bytes) {
    if (!("CompressionStream" in window)) {
      throw new Error('CompressionStream("gzip") not available in this browser context.');
    }
    const cs = new CompressionStream("gzip");
    const stream = new Blob([bytes]).stream().pipeThrough(cs);
    const ab = await new Response(stream).arrayBuffer();
    return new Uint8Array(ab);
  }

  // More robust base64 for Uint8Array
  function base64FromBytes(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  async function encodeQuery(queryText) {
    const bytes = utf16leBytes(queryText);   // FIXED
    const gz = await gzipBytes(bytes);
    return base64FromBytes(gz);
  }

  function getTidFromCurrentUrl() {
    let tid = "";
    try {
      const cur = new URL(location.href);
      tid = cur.searchParams.get("tid") || "";
    } catch {
      tid = "";
    }
    return tid;
  }

  function computeMissing(q, kvp) {
    const reqKeys = q.requiredKeys || [];
    return reqKeys.filter((k) => !(k in kvp) || kvp[k] === "");
  }

  function ensureArray(x) {
    return Array.isArray(x) ? x : [];
  }

  function normalizeLibrary(lib) {
    return ensureArray(lib)
      .map((q) => ({
        id: String(q.id || ""),
        name: String(q.name || q.id || "Unnamed"),
        requiredKeys: ensureArray(q.requiredKeys).map(String),
        template: String(q.template || ""),
      }))
      .filter((q) => q.id && q.template);
  }

  function buildUI(opts) {
    const id = opts.id || DEFAULT_ID;
    const rootUrl = opts.rootUrl || DEFAULT_ROOT_URL;
    const queryLibrary = normalizeLibrary(opts.queryLibrary || DEFAULT_QUERY_LIBRARY);

    if (document.getElementById(id)) return null;

    const tid = getTidFromCurrentUrl();
    if (!tid) {
      throw new Error("tid not found on current URL (?tid=...). Open Advanced Hunting first (or ensure tid is present).");
    }

    const modal = document.createElement("div");
    modal.id = id;
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-label", "KQL query assistant");
    modal.style.cssText = [
      "position:fixed",
      "left:24px",
      "top:24px",
      "width:760px",
      "max-width:calc(100vw - 24px*2)",
      "background:#111827",
      "color:#F9FAFB",
      "border:1px solid rgba(255,255,255,0.18)",
      "border-radius:12px",
      "box-shadow:0 18px 60px rgba(0,0,0,0.55)",
      "z-index:2147483647",
      "font:13px/1.35 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial",
      "overflow:hidden",
    ].join(";");

    modal.innerHTML = `
      <div id="${id}__hdr" style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;background:#0B1220;cursor:move;user-select:none;">
        <div style="display:flex;flex-direction:column;min-width:0;">
          <div style="font-weight:700;letter-spacing:.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">KQL query assistant</div>
          <div style="opacity:.75;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escHtml(rootUrl)} (tid from current URL)</div>
        </div>
        <button id="${id}__x" type="button" title="Close" style="appearance:none;border:0;background:transparent;color:#F9FAFB;font-size:18px;line-height:18px;padding:6px 8px;border-radius:8px;cursor:pointer;">×</button>
      </div>

      <div style="padding:12px;display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div style="display:flex;flex-direction:column;gap:8px;min-width:0;">
          <div style="display:flex;align-items:baseline;justify-content:space-between;gap:10px;">
            <div style="font-weight:700;">Inputs (KVP)</div>
            <div style="opacity:.75;font-size:12px;white-space:nowrap;">Format: <code style="background:rgba(255,255,255,.08);padding:2px 6px;border-radius:6px;">key=value</code></div>
          </div>
          <textarea id="${id}__kvp" spellcheck="false"
            style="width:100%;height:190px;resize:vertical;min-height:140px;max-height:55vh;background:#0B1220;color:#F9FAFB;border:1px solid rgba(255,255,255,0.18);border-radius:10px;padding:10px;outline:none;"
            placeholder="device=MY-LAPTOP\nip=1.2.3.4\nsha256=...\n"></textarea>
          <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;">
            <button id="${id}__clear" type="button" style="appearance:none;border:1px solid rgba(255,255,255,0.18);background:transparent;color:#F9FAFB;padding:8px 10px;border-radius:10px;cursor:pointer;">Clear</button>
          </div>
        </div>

        <div style="display:flex;flex-direction:column;gap:8px;min-width:0;">
          <div style="display:flex;align-items:baseline;justify-content:space-between;gap:10px;">
            <div style="font-weight:700;">KQL template</div>
            <div id="${id}__req" style="opacity:.75;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"></div>
          </div>

          <input id="${id}__filter" type="text" placeholder="Filter templates…"
            style="width:100%;background:#0B1220;color:#F9FAFB;border:1px solid rgba(255,255,255,0.18);border-radius:10px;padding:8px 10px;outline:none;" />

          <select id="${id}__sel" size="7"
            style="width:100%;background:#0B1220;color:#F9FAFB;border:1px solid rgba(255,255,255,0.18);border-radius:10px;padding:8px 10px;outline:none;"></select>

          <div style="font-weight:700;">Preview</div>
          <textarea id="${id}__preview" spellcheck="false" readonly
            style="width:100%;height:190px;resize:vertical;min-height:140px;max-height:55vh;background:#0B1220;color:#F9FAFB;border:1px solid rgba(255,255,255,0.18);border-radius:10px;padding:10px;outline:none;opacity:.95;"></textarea>

          <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;">
            <button id="${id}__copy" type="button" style="appearance:none;border:1px solid rgba(255,255,255,0.18);background:transparent;color:#F9FAFB;padding:8px 10px;border-radius:10px;cursor:pointer;">Copy KQL</button>
            <button id="${id}__go" type="button" style="appearance:none;border:0;background:#2563EB;color:white;padding:8px 12px;border-radius:10px;cursor:pointer;font-weight:700;">Submit → Advanced Hunting</button>
          </div>
        </div>

        <div style="grid-column:1 / -1;display:flex;flex-direction:column;gap:6px;">
          <div id="${id}__status" style="display:none;color:#A7F3D0;font-size:12px;"></div>
          <div id="${id}__err" style="display:none;color:#FCA5A5;font-size:12px;"></div>
        </div>
      </div>
    `;

    document.documentElement.appendChild(modal);

    const hdr = modal.querySelector(`#${id}__hdr`);
    const kvpTA = modal.querySelector(`#${id}__kvp`);
    const filterIn = modal.querySelector(`#${id}__filter`);
    const sel = modal.querySelector(`#${id}__sel`);
    const req = modal.querySelector(`#${id}__req`);
    const preview = modal.querySelector(`#${id}__preview`);
    const status = modal.querySelector(`#${id}__status`);
    const err = modal.querySelector(`#${id}__err`);
    const btnGo = modal.querySelector(`#${id}__go`);

    let statusTimer = null;
    function setStatus(msg) {
      status.textContent = msg;
      status.style.display = "block";
      if (statusTimer) clearTimeout(statusTimer);
      statusTimer = setTimeout(() => {
        status.style.display = "none";
        status.textContent = "";
      }, 1600);
    }
    function setError(msg) {
      err.textContent = msg;
      err.style.display = "block";
    }
    function clearError() {
      err.textContent = "";
      err.style.display = "none";
    }

    let drag = null;
    hdr.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      if (e.target && e.target.id === `${id}__x`) return;
      const r = modal.getBoundingClientRect();
      drag = { dx: e.clientX - r.left, dy: e.clientY - r.top };
      hdr.setPointerCapture(e.pointerId);
      e.preventDefault();
    });
    hdr.addEventListener("pointermove", (e) => {
      if (!drag) return;
      const w = modal.offsetWidth;
      const h = modal.offsetHeight;
      const x = clamp(e.clientX - drag.dx, 8, window.innerWidth - w - 8);
      const y = clamp(e.clientY - drag.dy, 8, window.innerHeight - h - 8);
      modal.style.left = x + "px";
      modal.style.top = y + "px";
    });
    hdr.addEventListener("pointerup", () => (drag = null));
    hdr.addEventListener("pointercancel", () => (drag = null));

    function close() {
      modal.remove();
    }
    modal.querySelector(`#${id}__x`).addEventListener("click", close);

    function getSelectedQuery() {
      return queryLibrary.find((q) => q.id === sel.value);
    }

    function render() {
      clearError();

      let kvp;
      try {
        kvp = parseKVP(kvpTA.value);
      } catch (e) {
        setError(String(e && e.message ? e.message : e));
        return;
      }

      const filter = String(filterIn.value || "").toLowerCase();
      const prevSel = sel.value;
      sel.innerHTML = "";

      const list = queryLibrary
        .filter((q) => {
          if (!filter) return true;
          return (q.name || "").toLowerCase().includes(filter) || (q.id || "").toLowerCase().includes(filter);
        })
        .map((q) => ({ q, missing: computeMissing(q, kvp) }));

      for (const item of list) {
        const q = item.q;
        const missing = item.missing;
        const opt = document.createElement("option");
        opt.value = q.id;
        opt.textContent = missing.length ? `${q.name}  (missing: ${missing.join(", ")})` : q.name;
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
        preview.value = "";
        req.textContent = "";
        return;
      }

      const missing = computeMissing(q, kvp);
      req.textContent =
        q.requiredKeys && q.requiredKeys.length
          ? missing.length
            ? `required: ${q.requiredKeys.join(", ")} (missing: ${missing.join(", ")})`
            : `required: ${q.requiredKeys.join(", ")}`
          : "required: (none)";

      preview.value = substitute(q.template, kvp);
    }

    modal.querySelector(`#${id}__clear`).addEventListener("click", () => {
      kvpTA.value = "";
      render();
      kvpTA.focus();
      setStatus("Cleared.");
    });

    kvpTA.addEventListener("input", render);
    filterIn.addEventListener("input", render);
    sel.addEventListener("change", render);

    modal.querySelector(`#${id}__copy`).addEventListener("click", async () => {
      clearError();
      try {
        await navigator.clipboard.writeText(preview.value || "");
        setStatus("Copied KQL to clipboard.");
      } catch {
        preview.focus();
        preview.select();
        document.execCommand("copy");
        setStatus("Copied (fallback).");
      }
    });

    async function go() {
      clearError();

      const q = getSelectedQuery();
      if (!q) return setError("Select a template first.");

      let kvp;
      try {
        kvp = parseKVP(kvpTA.value);
      } catch (e) {
        return setError(String(e && e.message ? e.message : e));
      }

      const missing = computeMissing(q, kvp);
      if (missing.length) return setError(`Missing required keys: ${missing.join(", ")}`);

      const finalQuery = substitute(q.template, kvp);

      btnGo.disabled = true;
      btnGo.style.opacity = "0.8";
      btnGo.textContent = "Encoding…";

      try {
        const encoded = await encodeQuery(finalQuery);
        const target = new URL(rootUrl);
        target.searchParams.set("tid", tid);
        target.searchParams.set("query", encoded);
        target.searchParams.set("timeRangeId", "month");
        location.href = target.toString();
      } catch (e) {
        setError(String(e && e.message ? e.message : e));
      } finally {
        btnGo.disabled = false;
        btnGo.style.opacity = "1";
        btnGo.textContent = "Submit → Advanced Hunting";
      }
    }

    btnGo.addEventListener("click", go);

    modal.addEventListener("keydown", (e) => {
      if (e.key === "Escape") close();
    });
    kvpTA.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") go();
    });

    render();
    kvpTA.focus();

    return {
      close,
      render,
      setLibrary(newLib) {
        const normalized = normalizeLibrary(newLib);
        queryLibrary.length = 0;
        for (const q of normalized) queryLibrary.push(q);
        render();
      },
    };
  }

  window.KqlQueryAssistant = {
    open: function (opts) {
      const options = opts || {};
      return buildUI({
        id: options.id || DEFAULT_ID,
        rootUrl: options.rootUrl || DEFAULT_ROOT_URL,
        queryLibrary: options.queryLibrary || DEFAULT_QUERY_LIBRARY,
      });
    },
  };
})();