/* ════════════════════════════════════════════════════════════
   app.js — Lógica del panel Watchdog de Red
   ════════════════════════════════════════════════════════════ */

"use strict";

// ── Estado global ──────────────────────────────────────────
let socket;
let allConnections      = [];
let selectedConn        = null;
let prevBytesSent       = 0;
let prevBytesRecv       = 0;
let activeCaptureSession = null;
let modalCallback       = null;
let capturePackets      = [];

// ── SocketIO ───────────────────────────────────────────────
function initSocket() {
  socket = io({ transports: ["websocket"] });

  socket.on("connect", () => {
    document.getElementById("ws-dot").classList.add("connected");
    toast("Conectado al servicio Watchdog", "ok");
  });

  socket.on("disconnect", () => {
    document.getElementById("ws-dot").classList.remove("connected");
    toast("Desconectado del servicio", "warn");
  });

  socket.on("server_info", (data) => {
    document.getElementById("my-ip").textContent = data.my_ip || "?";
    if (!data.scapy) {
      document.getElementById("badge-scapy").style.color = "#ff9800";
    }
  });

  socket.on("connections_update", (data) => {
    allConnections = data.connections || [];
    scheduleRender();
    updateStats(data.stats || {});
    document.getElementById("my-ip").textContent = data.my_ip || "?";
  });

  socket.on("action_result", handleActionResult);

  socket.on("packet", (data) => {
    if (data.session_id === activeCaptureSession) {
      prependPacketRow(data.packet);
    }
  });
}

// ── Estadísticas en topbar ─────────────────────────────────
function updateStats(stats) {
  const ext = allConnections.filter(c => c.is_external).length;
  document.getElementById("cnt-total").textContent    = allConnections.length;
  document.getElementById("cnt-external").textContent = ext;
  if (stats.bytes_sent !== undefined) {
    document.getElementById("stat-sent").textContent = fmtBytes(stats.bytes_sent);
    document.getElementById("stat-recv").textContent = fmtBytes(stats.bytes_recv);
  }
}

// ── Render debounced con requestAnimationFrame ─────────────
let _renderScheduled = false;
function scheduleRender() {
  if (_renderScheduled) return;
  _renderScheduled = true;
  requestAnimationFrame(() => {
    _renderScheduled = false;
    renderConnections();
  });
}

// Fingerprint ligero para detectar si una fila cambió (geo, status)
function connFingerprint(c) {
  const geo = c.geo || {};
  return `${c.status}|${geo.country}|${geo.org}|${geo.flag}|${c.hostname}`;
}

// ── Renderizar tabla de conexiones ─────────────────────────
// Mapa de fingerprints para evitar re-render innecesario
const _rowFingerprints = {};

function renderConnections() {
  const filterVal = document.getElementById("filter-input").value.toLowerCase();
  const onlyExt   = document.getElementById("chk-external").checked;
  const tbody     = document.getElementById("conn-tbody");

  // Índice rápido de filas existentes
  const existingKeys = {};
  tbody.querySelectorAll("tr[data-key]").forEach(tr => { existingKeys[tr.dataset.key] = tr; });

  const filtered = allConnections.filter(c => {
    if (onlyExt && !c.is_external) return false;
    if (!filterVal) return true;
    const hay = [c.process, c.remote_ip, c.hostname,
      c.local, c.remote, c.geo?.country, c.geo?.org].join(" ").toLowerCase();
    return hay.includes(filterVal);
  });

  const filteredKeys = new Set(filtered.map(c => c.key));

  // Eliminar filas que ya no están
  Object.keys(existingKeys).forEach(k => {
    if (!filteredKeys.has(k)) {
      existingKeys[k].remove();
      delete _rowFingerprints[k];
    }
  });

  // Actualizar o crear filas
  filtered.forEach(c => {
    const fp  = connFingerprint(c);
    let tr    = existingKeys[c.key];

    if (!tr) {
      // Fila nueva
      tr = document.createElement("tr");
      tr.dataset.key = c.key;
      if (c.is_external) {
        tr.classList.add("external", "new-conn");
        setTimeout(() => tr.classList.remove("new-conn"), 1200);
      }
      tr.innerHTML = buildRowHTML(c);
      tr.addEventListener("click", (e) => {
        // No propagar si se hizo clic en un botón de acción
        if (e.target.tagName !== "BUTTON") selectConn(c);
      });
      tbody.prepend(tr);
      _rowFingerprints[c.key] = fp;
    } else if (_rowFingerprints[c.key] !== fp) {
      // Solo re-renderizar si algo cambió (geo, status)
      const wasSelected = tr.classList.contains("selected");
      tr.innerHTML = buildRowHTML(c);
      tr.onclick = (e) => { if (e.target.tagName !== "BUTTON") selectConn(c); };
      if (wasSelected) tr.classList.add("selected");
      _rowFingerprints[c.key] = fp;
    }
    // Actualizar referencia del elemento seleccionado
    if (selectedConn && selectedConn.key === c.key) {
      tr.classList.add("selected");
      selectedConn = c;
      renderDetail(c);
    }
  });
}

function buildRowHTML(c) {
  const geo   = c.geo || {};
  const flag  = geo.flag ? `<span title="${geo.country}">${geo.flag}</span>` : "";
  const status= `<span class="status-badge status-${c.status || "OTHER"}">${c.status || "?"}</span>`;
  const host  = c.hostname !== c.remote_ip ? c.hostname : "";
  return `
    <td><span title="${c.exe}">${esc(c.process)}</span></td>
    <td><code>${c.pid}</code></td>
    <td><code style="font-size:10px">${esc(c.local)}</code></td>
    <td><code style="font-size:10px">${esc(c.remote)}</code></td>
    <td style="max-width:160px" title="${esc(host)}">${esc(host.substring(0,32))}</td>
    <td>${flag} <span style="font-size:11px">${esc(geo.country || "")}</span></td>
    <td style="max-width:130px;overflow:hidden;text-overflow:ellipsis" title="${esc(geo.org || "")}">${esc((geo.org||"").substring(0,22))}</td>
    <td>${status}</td>
    <td>
      <div style="display:flex;gap:4px;flex-wrap:wrap">
        ${c.pid ? `<button class="btn-action btn-kill" onclick="askKill(event,${c.pid},'${esc(c.process)}')">✕ Matar</button>` : ""}
        ${c.remote_ip ? `<button class="btn-action btn-block" onclick="askBlockIP(event,'${esc(c.remote_ip)}')">🚫 Bloquear IP</button>` : ""}
        ${c.exe ? `<button class="btn-action btn-block" onclick="askBlockProc(event,'${esc(c.exe)}','${esc(c.process)}')">🔒 Bloquear Proc</button>` : ""}
        ${c.remote_ip ? `<button class="btn-action btn-inspect" onclick="startCapture(event,'${esc(c.remote_ip)}')">🔍 Inspeccionar</button>` : ""}
      </div>
    </td>`;
}

function filterConnections() { scheduleRender(); }
function manualRefresh()     { scheduleRender(); }

// ── Selección y panel de detalle ───────────────────────────
function selectConn(c) {
  selectedConn = c;
  document.querySelectorAll("#conn-tbody tr").forEach(tr => {
    tr.classList.toggle("selected", tr.dataset.key === c.key);
  });
  renderDetail(c);
}

function renderDetail(c) {
  const geo  = c.geo || {};
  const proc = c.proc_detail || {};
  document.getElementById("detail-content").innerHTML = `
    <div class="detail-section">
      <span class="flag-big">${geo.flag || "🌐"}</span>
      <div class="country-name">${esc(geo.country || "Desconocido")}</div>
      <div class="org-name">${esc(geo.org || "")}</div>
    </div>

    <div class="detail-section">
      <h4>Conexión</h4>
      <div class="detail-row"><span class="key">Estado</span><span class="val">
        <span class="status-badge status-${c.status||"OTHER"}">${c.status||"?"}</span>
      </span></div>
      <div class="detail-row"><span class="key">Local</span><span class="val">${esc(c.local)}</span></div>
      <div class="detail-row"><span class="key">Remoto</span><span class="val">${esc(c.remote)}</span></div>
      <div class="detail-row"><span class="key">IP Remota</span><span class="val">${esc(c.remote_ip)}</span></div>
      <div class="detail-row"><span class="key">Hostname</span><span class="val">${esc(c.hostname)}</span></div>
      <div class="detail-row"><span class="key">País</span><span class="val">${esc(geo.country||"")}</span></div>
      <div class="detail-row"><span class="key">Ciudad</span><span class="val">${esc(geo.city||"")}</span></div>
      <div class="detail-row"><span class="key">Org/ISP</span><span class="val">${esc(geo.org||"")}</span></div>
      ${geo.lat ? `<div class="detail-row"><span class="key">Coordenadas</span><span class="val">${geo.lat}, ${geo.lon}</span></div>` : ""}
    </div>

    <div class="detail-section">
      <h4>Proceso</h4>
      <div class="detail-row"><span class="key">Nombre</span><span class="val">${esc(proc.name||c.process)}</span></div>
      <div class="detail-row"><span class="key">PID</span><span class="val">${c.pid}</span></div>
      <div class="detail-row"><span class="key">Usuario</span><span class="val">${esc(proc.username||c.username)}</span></div>
      <div class="detail-row"><span class="key">CPU</span><span class="val">${proc.cpu||0}%</span></div>
      <div class="detail-row"><span class="key">RAM</span><span class="val">${proc.mem_mb||0} MB</span></div>
      <div class="detail-row"><span class="key">Iniciado</span><span class="val">${esc(proc.created||"")}</span></div>
      ${proc.cmdline ? `<div class="detail-row"><span class="key">Cmdline</span><span class="val" style="font-size:9px;word-break:break-all">${esc(proc.cmdline.substring(0,120))}</span></div>` : ""}
      <div class="detail-row"><span class="key">Exe</span><span class="val" style="font-size:9px;word-break:break-all">${esc((proc.exe||c.exe||"").substring(0,80))}</span></div>
    </div>

    <div class="detail-section">
      <h4>Acciones</h4>
      <div class="detail-actions">
        ${c.pid ? `<button class="btn-action btn-kill" onclick="askKill(event,${c.pid},'${esc(c.process)}')">✕ Matar Proceso</button>` : ""}
        ${c.remote_ip ? `<button class="btn-action btn-block" onclick="askBlockIP(event,'${esc(c.remote_ip)}')">🚫 Bloquear IP</button>` : ""}
        ${c.exe ? `<button class="btn-action btn-block" onclick="askBlockProc(event,'${esc(c.exe)}','${esc(c.process)}')">🔒 Bloquear Proc en Firewall</button>` : ""}
        ${c.remote_ip ? `<button class="btn-action btn-inspect" onclick="startCapture(event,'${esc(c.remote_ip)}')">🔍 Inspeccionar Tráfico</button>` : ""}
        ${c.remote_ip ? `<button class="btn-action btn-inspect" onclick="showIPHistory('${esc(c.remote_ip)}')">📜 Ver Historial IP</button>` : ""}
      </div>
    </div>`;
}

function closeDetail() {
  selectedConn = null;
  document.querySelectorAll("#conn-tbody tr").forEach(tr => tr.classList.remove("selected"));
  document.getElementById("detail-content").innerHTML =
    `<p class="hint-center">Haz clic en una conexión para ver detalles</p>`;
}

// ── Acciones ───────────────────────────────────────────────
function askKill(e, pid, name) {
  e.stopPropagation();
  openModal(`¿Terminar proceso?`,
    `<b>${esc(name)}</b> (PID ${pid}) será terminado. Los datos sin guardar se perderán.`,
    () => { socket.emit("kill_process", { pid, process: name }); });
}

function askBlockIP(e, ip) {
  if (e) e.stopPropagation();
  openModal("¿Bloquear IP?",
    `Se añadirá una regla en el Firewall de Windows para bloquear toda comunicación con <b>${esc(ip)}</b>.`,
    () => { socket.emit("block_ip", { ip, direction: "both" }); });
}

function askBlockProc(e, exe, name) {
  if (e) e.stopPropagation();
  openModal("¿Bloquear proceso en Firewall?",
    `El proceso <b>${esc(name)}</b> no podrá acceder a internet.<br><small>${esc(exe)}</small>`,
    () => { socket.emit("block_process", { exe, process: name }); });
}

function manualBlockIP() {
  const ip  = document.getElementById("manual-block-ip").value.trim();
  const dir = document.getElementById("block-dir").value;
  if (!ip) return toast("Ingresa una IP válida", "warn");
  socket.emit("block_ip", { ip, direction: dir });
  document.getElementById("manual-block-ip").value = "";
}

function unblockIP(ip) {
  socket.emit("unblock_ip", { ip });
  setTimeout(loadBlocked, 800);
}

// ── Captura de paquetes ────────────────────────────────────
function startCapture(e, ip) {
  if (e) e.stopPropagation();
  socket.emit("start_capture", { ip });
  switchTab("tab-capture", document.querySelector(`[data-tab="tab-capture"]`));
  toast(`Iniciando captura para ${ip}…`, "ok");
}

function prependPacketRow(pkt) {
  capturePackets.unshift(pkt);
  const tbody = document.getElementById("pkt-tbody");
  const tr    = document.createElement("tr");
  tr.dataset.pktId = pkt.id || capturePackets.length;
  const dirClass   = pkt.direction === "OUT" ? "dir-OUT" : "dir-IN";
  const protoClass = `proto-${pkt.proto||"TCP"}`;
  const dirArrow   = pkt.direction === "OUT" ? "↑" : "↓";
  tr.innerHTML = `
    <td><code style="font-size:10px">${esc(pkt.ts||"")}</code></td>
    <td><span class="${dirClass}">${dirArrow} ${pkt.direction||""}</span></td>
    <td><span class="${protoClass}" style="font-weight:700">${esc(pkt.proto||"")}</span></td>
    <td><code style="font-size:10px">${esc(pkt.src||"")}</code></td>
    <td><code style="font-size:10px">${esc(pkt.dst||"")}</code></td>
    <td>${fmtBytes(pkt.size||0)}</td>
    <td title="${esc(pkt.summary||"")}" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc((pkt.summary||"").substring(0,60))}</td>
    <td class="payload-cell" title="${esc(pkt.raw||"")}">${esc((pkt.raw||"").substring(0,40))}</td>
  `;
  // Click para abrir detalle del paquete
  tr.style.cursor = "pointer";
  tr.addEventListener("click", () => showPacketDetail(pkt));
  tr.addEventListener("mouseenter", () => tr.style.background = "var(--row-hover)");
  tr.addEventListener("mouseleave", () => tr.style.background = "");
  tbody.prepend(tr);
  while (tbody.rows.length > 300) tbody.deleteRow(tbody.rows.length - 1);
}

// ── Modal detalle de paquete ────────────────────────────────
function showPacketDetail(pkt) {
  const dir = pkt.direction === "OUT";
  const dirLabel  = dir ? "📤 ENVIANDO" : "📥 RECIBIENDO";
  const dirColor  = dir ? "var(--red)" : "var(--green)";
  const details   = pkt.details || {};

  // ── Interpretación humana principal ──────────────────────
  let humanBlock = `<div class="pkt-human">${esc(pkt.human || pkt.summary || "")}</div>`;

  // ── Bloque por protocolo ──────────────────────────────────
  let protoBlock = "";

  if (pkt.proto === "DNS") {
    const q = (details.dns_queries||[]).map(d => `<li>🔍 <b>${esc(d)}</b></li>`).join("");
    const a = (details.dns_answers||[]).map(d => `<li>✅ ${esc(d)}</li>`).join("");
    protoBlock = `
      <div class="pkt-section">
        <div class="pkt-section-title">Consulta DNS</div>
        ${q ? `<div class="pkt-label">Dominios consultados:</div><ul class="pkt-list">${q}</ul>` : ""}
        ${a ? `<div class="pkt-label">Respuestas obtenidas:</div><ul class="pkt-list">${a}</ul>` : ""}
      </div>`;
  }

  if (pkt.proto === "HTTP" && details.http_method) {
    const headers = details.http_headers || {};
    const hdrRows = Object.entries(headers)
      .map(([k,v]) => `<div class="pkt-header-row"><span class="pkt-hkey">${esc(k)}</span><span class="pkt-hval">${esc(String(v).substring(0,200))}</span></div>`)
      .join("");
    protoBlock = `
      <div class="pkt-section">
        <div class="pkt-section-title">Solicitud HTTP</div>
        <div class="pkt-http-line">
          <span class="http-method">${esc(details.http_method)}</span>
          <span class="http-path">${esc(details.http_host)}${esc(details.http_path)}</span>
          <span class="http-ver">${esc(details.http_version)}</span>
        </div>
        ${hdrRows ? `<div class="pkt-label" style="margin-top:10px">Headers enviados al servidor:</div><div class="pkt-headers">${hdrRows}</div>` : ""}
        ${details.http_body ? `<div class="pkt-label" style="margin-top:10px">Cuerpo (body):</div><pre class="pkt-raw-text">${esc(details.http_body.substring(0,800))}</pre>` : ""}
      </div>`;
  }

  if (pkt.proto === "HTTP" && details.http_status) {
    const headers = details.http_headers || {};
    const hdrRows = Object.entries(headers)
      .map(([k,v]) => `<div class="pkt-header-row"><span class="pkt-hkey">${esc(k)}</span><span class="pkt-hval">${esc(String(v).substring(0,200))}</span></div>`)
      .join("");
    protoBlock = `
      <div class="pkt-section">
        <div class="pkt-section-title">Respuesta HTTP</div>
        <div class="pkt-http-line">
          <span class="http-ver">${esc(details.http_version)}</span>
          <span class="http-method" style="color:${parseInt(details.http_status)>=400?'var(--red)':'var(--green)'}">${esc(details.http_status)} ${esc(details.http_reason)}</span>
        </div>
        ${hdrRows ? `<div class="pkt-label" style="margin-top:10px">Headers del servidor:</div><div class="pkt-headers">${hdrRows}</div>` : ""}
        ${details.http_body ? `<div class="pkt-label" style="margin-top:10px">Cuerpo de respuesta:</div><pre class="pkt-raw-text">${esc(details.http_body.substring(0,800))}</pre>` : ""}
      </div>`;
  }

  if (pkt.proto === "TLS") {
    const sni = details.tls_sni;
    protoBlock = `
      <div class="pkt-section">
        <div class="pkt-section-title">Conexión TLS/HTTPS cifrada</div>
        ${sni ? `<div class="pkt-label">Destino (SNI — Server Name Indication):</div>
          <div class="pkt-sni">🔒 ${esc(sni)}</div>
          <div class="pkt-label" style="margin-top:8px">¿Qué significa?</div>
          <div class="pkt-hint">SNI es la parte del handshake TLS que revela a qué dominio se conecta aunque el tráfico esté cifrado.</div>` :
          `<div class="pkt-hint">El contenido está cifrado con TLS. Solo se sabe que se comunica con el servidor en el puerto 443.</div>`}
      </div>`;
  }

  if (pkt.proto === "TCP" && details.tcp_flags) {
    protoBlock = `
      <div class="pkt-section">
        <div class="pkt-section-title">Paquete TCP</div>
        <div class="pkt-label">Flags técnicos:</div>
        <div class="pkt-sni" style="font-size:12px">${esc(details.tcp_flags)}</div>
        <div class="pkt-label" style="margin-top:8px">Significado:</div>
        <div class="pkt-hint">${esc(details.tcp_flags_human)}</div>
      </div>`;
  }

  // ── Capas del paquete ─────────────────────────────────────
  const layersHtml = (pkt.layers || []).map((l, i) =>
    `<div class="pkt-layer" style="padding-left:${i*12}px">
       <span class="pkt-layer-dot"></span>${esc(l)}
     </div>`
  ).join("");

  // ── Hex dump ──────────────────────────────────────────────
  const hexDump = pkt.hex_dump
    ? `<div class="pkt-section">
         <div class="pkt-section-title">Hex Dump (payload raw)</div>
         <pre class="pkt-hex">${esc(pkt.hex_dump)}</pre>
       </div>`
    : "";

  // ── Texto en crudo ────────────────────────────────────────
  const rawText = pkt.raw_full
    ? `<div class="pkt-section">
         <div class="pkt-section-title">Payload en texto</div>
         <pre class="pkt-raw-text">${esc(pkt.raw_full.substring(0,1500))}</pre>
       </div>`
    : "";

  const content = `
    <div class="pkt-modal-header" style="border-left: 4px solid ${dirColor}">
      <div class="pkt-dir-label" style="color:${dirColor}">${dirLabel}</div>
      <div class="pkt-meta">
        <span class="proto-${pkt.proto}" style="font-weight:700;font-size:13px">${esc(pkt.proto)}</span>
        &nbsp;·&nbsp; ${esc(pkt.src)} <span style="color:var(--text-dim)">→</span> ${esc(pkt.dst)}
        &nbsp;·&nbsp; ${fmtBytes(pkt.size||0)}
        &nbsp;·&nbsp; <span style="color:var(--text-dim)">${esc(pkt.ts)}</span>
      </div>
    </div>

    <div class="pkt-section" style="border-left:4px solid ${dirColor}">
      <div class="pkt-section-title">📖 ¿Qué está haciendo este paquete?</div>
      ${humanBlock}
    </div>

    ${protoBlock}

    <div class="pkt-section">
      <div class="pkt-section-title">Capas del protocolo</div>
      <div class="pkt-layers">${layersHtml}</div>
    </div>

    ${hexDump}
    ${rawText}
  `;

  openPacketModal(`Paquete #${pkt.id || "?"} — ${esc(pkt.proto)}`, content);
}

function openPacketModal(title, content) {
  let modal = document.getElementById("pkt-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "pkt-modal";
    modal.className = "pkt-modal-overlay";
    modal.innerHTML = `
      <div class="pkt-modal-box">
        <div class="pkt-modal-top">
          <span id="pkt-modal-title" class="pkt-modal-title-text"></span>
          <button onclick="document.getElementById('pkt-modal').classList.add('hidden')"
                  class="btn-close" style="font-size:18px">✕</button>
        </div>
        <div id="pkt-modal-body" class="pkt-modal-body"></div>
      </div>`;
    modal.addEventListener("click", e => {
      if (e.target === modal) modal.classList.add("hidden");
    });
    document.body.appendChild(modal);
  }
  document.getElementById("pkt-modal-title").textContent = title;
  document.getElementById("pkt-modal-body").innerHTML = content;
  modal.classList.remove("hidden");
}

// ── Cargar datos de tabs ───────────────────────────────────
async function loadHistory(ip=null) {
  const url = ip ? `/api/history?ip=${encodeURIComponent(ip)}&limit=300` : "/api/history?limit=300";
  const rows = await fetchJSON(url);
  const tbody = document.getElementById("hist-tbody");
  tbody.innerHTML = "";
  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(r.ts||"")}</td>
      <td>${esc(r.process||"")}</td>
      <td><code style="font-size:10px">${esc(r.remote_ip||"")}</code></td>
      <td style="max-width:140px;overflow:hidden;text-overflow:ellipsis">${esc(r.hostname||"")}</td>
      <td>${esc(r.geo_flag||"")} ${esc(r.country||"")}</td>
      <td>${esc((r.org||"").substring(0,28))}</td>
      <td><code>${r.remote_port||""}</code></td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadBlocked() {
  const rows = await fetchJSON("/api/blocked");
  const tbody = document.getElementById("blocked-tbody");
  tbody.innerHTML = "";
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="hint-center">Sin bloqueos activos</td></tr>`;
    return;
  }
  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(r.ts||"")}</td>
      <td><code>${esc(r.ip||r.name||"")}</code></td>
      <td>${esc(r.process||"")}</td>
      <td>${esc(r.direction||"")}</td>
      <td>
        ${r.ip ? `<button class="btn-action btn-unblock" onclick="unblockIP('${esc(r.ip)}')">✓ Desbloquear</button>` : ""}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadTop() {
  const rows = await fetchJSON("/api/top");
  const tbody = document.getElementById("top-tbody");
  tbody.innerHTML = "";
  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code style="font-size:10px">${esc(r.remote_ip||"")}</code></td>
      <td style="max-width:140px;overflow:hidden;text-overflow:ellipsis">${esc(r.hostname||"")}</td>
      <td>${esc(r.geo_flag||"")} ${esc(r.country||"")}</td>
      <td>${esc((r.org||"").substring(0,28))}</td>
      <td><b style="color:var(--accent)">${r.total}</b></td>
      <td style="font-size:10px;color:var(--text-dim)">${esc((r.processes||"").substring(0,50))}</td>
      <td>
        <button class="btn-action btn-block" onclick="askBlockIP(null,'${esc(r.remote_ip)}')">🚫 Bloquear</button>
        <button class="btn-action btn-inspect" onclick="showIPHistory('${esc(r.remote_ip)}')">📜 Historial</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadEvents() {
  const rows = await fetchJSON("/api/events");
  const tbody = document.getElementById("events-tbody");
  tbody.innerHTML = "";
  rows.forEach(r => {
    const tr = document.createElement("tr");
    const okIcon = r.ok ? `<span style="color:var(--green)">✓</span>` : `<span style="color:var(--red)">✗</span>`;
    tr.innerHTML = `
      <td>${esc(r.ts||"")}</td>
      <td><code>${esc(r.event_type||"")}</code></td>
      <td>${esc(r.target||"")}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;font-size:11px">${esc(r.detail||"")}</td>
      <td>${okIcon}</td>
    `;
    tbody.appendChild(tr);
  });
}

function showIPHistory(ip) {
  switchTab("tab-history", document.querySelector(`[data-tab="tab-history"]`));
  loadHistory(ip).then(() => toast(`Historial de ${ip}`, "ok"));
}

// ── Manejar resultados de acciones ─────────────────────────
function handleActionResult(data) {
  const type = data.action;
  const msg  = data.msg || (data.ok ? "OK" : "Error");
  toast(msg, data.ok ? "ok" : "error");

  if (type === "block_ip" || type === "unblock_ip") loadBlocked();
  if (type === "block_process") loadBlocked();
  if (type === "start_capture" && data.ok) {
    activeCaptureSession = data.session_id;
    document.getElementById("capture-status-bar").textContent =
      `▶ Capturando tráfico de ${data.target_ip} — sesión: ${data.session_id}`;
    document.getElementById("capture-status-bar").className = "status-bar ok";
    addSessionChip(data.session_id, data.target_ip);
  }
  if (type === "stop_capture") {
    document.getElementById("capture-status-bar").textContent = "Captura detenida";
    document.getElementById("capture-status-bar").className = "status-bar warn";
  }
}

// ── Session chips ──────────────────────────────────────────
function addSessionChip(sessionId, ip) {
  const list = document.getElementById("capture-sessions-list");
  const chip = document.createElement("div");
  chip.className = "session-chip active-cap";
  chip.id = `chip-${sessionId}`;
  chip.innerHTML = `${ip} <button style="background:none;border:1px solid var(--red);border-radius:3px;color:var(--red);cursor:pointer;padding:1px 4px;font-size:10px" onclick="stopCapture('${sessionId}', this.parentElement)">⏹</button>`;
  list.appendChild(chip);
}

function stopCapture(sessionId, chipEl) {
  socket.emit("stop_capture", { session_id: sessionId });
  if (chipEl) chipEl.remove();
  if (activeCaptureSession === sessionId) activeCaptureSession = null;
}

// ── Tabs ───────────────────────────────────────────────────
function switchTab(tabId, btn) {
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  const tab = document.getElementById(tabId);
  if (tab) tab.classList.add("active");
  if (btn) btn.classList.add("active");
  // Auto-cargar datos al cambiar de tab
  if (tabId === "tab-history") loadHistory();
  if (tabId === "tab-blocked") loadBlocked();
  if (tabId === "tab-top")     loadTop();
  if (tabId === "tab-events")  loadEvents();
}

// ── Modal ──────────────────────────────────────────────────
function openModal(title, body, onConfirm) {
  document.getElementById("modal-title").textContent = title;
  document.getElementById("modal-body").innerHTML    = body;
  document.getElementById("modal-overlay").classList.remove("hidden");
  modalCallback = onConfirm;
  document.getElementById("modal-confirm").onclick = () => {
    if (modalCallback) modalCallback();
    closeModal();
  };
}
function closeModal() {
  document.getElementById("modal-overlay").classList.add("hidden");
  modalCallback = null;
}

// ── Toast ──────────────────────────────────────────────────
function toast(msg, type = "info") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById("toast-container").appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Utilidades ─────────────────────────────────────────────
function esc(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function fmtBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + " KB";
  if (bytes < 1024*1024*1024) return (bytes/1024/1024).toFixed(1) + " MB";
  return (bytes/1024/1024/1024).toFixed(2) + " GB";
}

async function fetchJSON(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) return [];
    return await r.json();
  } catch (e) {
    return [];
  }
}

// ── Init ───────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initSocket();
  loadBlocked(); // cargar initial
});
