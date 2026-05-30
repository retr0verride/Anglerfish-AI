// Anglerfish AI dashboard client.
//
// Polls /api/stats, /api/threats, /api/credentials on a slow cadence;
// subscribes to /ws/events for the live command stream. Defensive
// against connection drops — exponential backoff up to 30 s and
// resync on every reopen.
"use strict";

const STATS_POLL_MS = 5000;
const TABLE_POLL_MS = 15000;
const COMMAND_STREAM_CAP = 200;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const statusEl = $("#ws-status");
const commandStream = $("#command-stream");
const threatTable = $("#threat-table");
const credentialsTable = $("#credentials-table");
const credentialsMeta = $("#credentials-meta");
const detailPanel = $("#detail-panel");
const detailBody = $("#detail-body");
const detailClose = $("#detail-close");
const clusterCanvas = $("#cluster-canvas");
const clusterMeta = $("#cluster-meta");

let wsBackoffMs = 1000;

function setStatus(text, kind) {
  if (!statusEl) return;
  statusEl.textContent = text;
  statusEl.dataset.status = kind;
}

async function fetchJSON(url) {
  const res = await fetch(url, { credentials: "same-origin" });
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}

async function refreshStats() {
  try {
    const stats = await fetchJSON("/api/stats");
    for (const card of $$("[data-stat]")) {
      const key = card.dataset.stat;
      const value = stats[key];
      const out = card.querySelector(".card__value");
      if (out) out.textContent = value ?? "—";
    }
  } catch (err) {
    console.warn("stats refresh failed:", err);
  }
}

function formatTimestamp(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

// HTML-escape before interpolating into innerHTML. Several call sites
// render attacker-controlled text (typed commands, bridge responses,
// submitted usernames/passwords); without escaping, markup in those
// fields executes in the operator's authenticated session. The CSP
// (script-src 'self') is the backstop; this function is the primary
// defence. tests/dashboard/test_spa_xss_browser.py pins the behaviour.
function escapeText(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function refreshThreats() {
  try {
    const threats = await fetchJSON("/api/threats?limit=50");
    threatTable.innerHTML = "";
    for (const t of threats) {
      const tr = document.createElement("tr");
      const techIds = (t.techniques || []).map((x) => x.id).join(", ");
      const score = Number(t.score) || 0;
      tr.innerHTML = `
        <td>
          <button type="button" class="session-link" data-session-id="${escapeText(t.session_id)}">
            <code>${escapeText(t.session_id).slice(0, 8)}</code>
          </button>
        </td>
        <td>
          <span class="score-bar"><span class="score-bar__fill" style="width:${score}%"></span></span>
          ${score}
        </td>
        <td>${t.persistence_attempted ? "yes" : "no"}</td>
        <td>${escapeText(techIds)}</td>
      `;
      threatTable.appendChild(tr);
    }
  } catch (err) {
    console.warn("threats refresh failed:", err);
  }
}

async function refreshCredentials() {
  try {
    const payload = await fetchJSON("/api/credentials?limit=100");
    if (!payload.configured) {
      credentialsMeta.textContent = "Credential intelligence DB not configured.";
      credentialsTable.innerHTML = "";
      return;
    }
    const stats = await fetchJSON("/api/credentials/stats");
    credentialsMeta.textContent =
      `${stats.total_attempts} attempts · ` +
      `${stats.unique_combinations} unique combos · ` +
      `${stats.unique_source_ips} source IPs`;
    credentialsTable.innerHTML = "";
    for (const r of payload.records) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${escapeText(r.source_ip)}</code></td>
        <td><code>${escapeText(r.username)}</code></td>
        <td><code>${escapeText(r.password)}</code></td>
        <td>${escapeText(r.attempt_count)}</td>
        <td>${escapeText(formatTimestamp(r.last_seen))}</td>
      `;
      credentialsTable.appendChild(tr);
    }
  } catch (err) {
    console.warn("credentials refresh failed:", err);
  }
}

function fmtMs(ms) {
  const n = Number(ms) || 0;
  if (n < 1000) return `${n} ms`;
  const totalSec = Math.floor(n / 1000);
  const min = Math.floor(totalSec / 60);
  const sec = totalSec % 60;
  return min > 0 ? `${min}m ${sec}s` : `${sec}s`;
}

// Render the aggregate /api/sessions/{id}/detail payload into the panel.
// Every dynamic value goes through escapeText before innerHTML; turns
// reuse the live-stream classes so they read identically.
function renderDetail(d) {
  const s = d.session || {};
  const sid = escapeText(s.session_id);
  const parts = [];

  parts.push(`
    <p class="detail__head">
      <code>${sid.slice(0, 8)}</code> · <code>${escapeText(s.source_ip)}</code>
      ${d.persona ? `<span class="badge">persona: ${escapeText(d.persona)}</span>` : ""}
    </p>
    <p class="meta">
      started ${escapeText(formatTimestamp(s.started_at))} ·
      last activity ${escapeText(formatTimestamp(s.last_activity_at))} ·
      time-wasted ${escapeText(fmtMs(d.time_wasted_ms))}
    </p>
  `);

  if (d.intent) {
    const tech = (d.intent.matched_techniques || []).map(escapeText).join(", ");
    parts.push(`
      <div class="detail__section">
        <h3>Intent · ${escapeText(d.intent.confidence)}</h3>
        <p>${escapeText(d.intent.summary)}</p>
        ${tech ? `<p class="meta">${tech}</p>` : ""}
      </div>
    `);
  }

  if (d.counter_deception) {
    const cd = d.counter_deception;
    parts.push(`
      <div class="detail__section">
        <h3>Counter-deception · ${escapeText(cd.mode)}</h3>
        <p class="meta">
          engaged ${escapeText(formatTimestamp(cd.engaged_at))} ·
          garbled ${escapeText(cd.garble_paths_count ?? "?")} paths
        </p>
      </div>
    `);
  }

  const tokens = d.honeytokens || [];
  if (tokens.length) {
    const rows = tokens
      .map(
        (h) =>
          `<li><code>${escapeText(h.id)}</code> · ${escapeText(h.kind)} · <code>${escapeText(h.placed_at)}</code></li>`,
      )
      .join("");
    parts.push(`
      <div class="detail__section">
        <h3>Honeytokens served</h3>
        <ul class="detail__list">${rows}</ul>
      </div>
    `);
  }

  const turns = d.turns || [];
  if (turns.length) {
    const rows = turns
      .map(
        (t) =>
          `<li class="is-${escapeText(t.source)}">
             <div class="stream__cmd">$ ${escapeText(t.command)}</div>
             <div class="stream__response">${escapeText(t.response)}</div>
           </li>`,
      )
      .join("");
    parts.push(`
      <div class="detail__section">
        <h3>Turns (${turns.length})</h3>
        <ol class="stream">${rows}</ol>
      </div>
    `);
  }

  const similar = d.similar || [];
  if (similar.length) {
    const links = similar
      .map((n) => {
        const nid = escapeText(n.session_id);
        const sim = (Number(n.similarity) || 0).toFixed(2);
        return `<button type="button" class="session-link" data-session-id="${nid}"><code>${nid.slice(0, 8)}</code></button> (${sim})`;
      })
      .join(" · ");
    parts.push(`
      <div class="detail__section">
        <h3>Similar sessions</h3>
        <p>${links}</p>
      </div>
    `);
  }

  detailBody.innerHTML = parts.join("");
}

async function openDetail(sessionId) {
  try {
    const detail = await fetchJSON(
      `/api/sessions/${encodeURIComponent(sessionId)}/detail`,
    );
    renderDetail(detail);
    if (detailPanel) {
      detailPanel.hidden = false;
      detailPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  } catch (err) {
    console.warn("session detail fetch failed:", err);
  }
}

function onSessionLinkClick(ev) {
  const link = ev.target.closest(".session-link");
  if (link && link.dataset.sessionId) {
    openDetail(link.dataset.sessionId);
  }
}

// --- Session cluster graph (Stage 13.2) ---
// Dependency-free force-directed layout on <canvas>: node colour encodes
// the intent label, radius encodes the threat score, clicking a node
// opens its detail panel. The layout runs a bounded number of cooling
// ticks then stops to spare CPU. It is a snapshot fetched on boot, not
// a live poll (re-running the layout would jump every node).
const CLUSTER_TICKS = 320;
const clusterState = { nodes: [], edges: [], byId: {}, tick: 0, raf: 0 };

function hashHue(text) {
  let h = 0;
  for (let i = 0; i < text.length; i += 1) {
    h = (h * 31 + text.charCodeAt(i)) % 360;
  }
  return h;
}

function nodeColor(intentLabel) {
  if (!intentLabel) return "#94a8c0"; // --text-dim for unlabelled sessions
  return `hsl(${hashHue(intentLabel)}, 70%, 58%)`;
}

function nodeRadius(score) {
  const s = Math.max(0, Math.min(100, Number(score) || 0));
  return 4 + (s / 100) * 11;
}

function clusterStep(width, height) {
  const nodes = clusterState.nodes;
  const n = nodes.length;
  if (n === 0) return;
  const k = Math.sqrt((width * height) / n); // ideal edge length
  for (let i = 0; i < n; i += 1) {
    const a = nodes[i];
    a.fx = 0;
    a.fy = 0;
    for (let j = 0; j < n; j += 1) {
      if (i === j) continue;
      const b = nodes[j];
      const dx = a.x - b.x;
      const dy = a.y - b.y;
      const dist = Math.hypot(dx, dy) || 0.01;
      const rep = (k * k) / dist;
      a.fx += (dx / dist) * rep;
      a.fy += (dy / dist) * rep;
    }
  }
  for (const e of clusterState.edges) {
    const a = clusterState.byId[e.a];
    const b = clusterState.byId[e.b];
    if (!a || !b) continue;
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    const dist = Math.hypot(dx, dy) || 0.01;
    const att = (dist * dist) / k;
    a.fx -= (dx / dist) * att;
    a.fy -= (dy / dist) * att;
    b.fx += (dx / dist) * att;
    b.fy += (dy / dist) * att;
  }
  const cx = width / 2;
  const cy = height / 2;
  const cool = Math.max(0.05, 1 - clusterState.tick / CLUSTER_TICKS);
  const maxStep = 12 * cool;
  for (const a of nodes) {
    a.fx += (cx - a.x) * 0.02;
    a.fy += (cy - a.y) * 0.02;
    const mag = Math.hypot(a.fx, a.fy) || 0.01;
    const step = Math.min(mag, maxStep);
    a.x = Math.max(16, Math.min(width - 16, a.x + (a.fx / mag) * step));
    a.y = Math.max(16, Math.min(height - 16, a.y + (a.fy / mag) * step));
  }
}

function clusterRender() {
  if (!clusterCanvas) return;
  const ctx = clusterCanvas.getContext("2d");
  if (!ctx) return;
  const w = clusterCanvas.width;
  const h = clusterCanvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.lineWidth = 1;
  for (const e of clusterState.edges) {
    const a = clusterState.byId[e.a];
    const b = clusterState.byId[e.b];
    if (!a || !b) continue;
    const alpha = 0.15 + 0.5 * (Number(e.similarity) || 0);
    ctx.strokeStyle = `rgba(34, 211, 238, ${alpha})`;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
  for (const node of clusterState.nodes) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
    ctx.fillStyle = node.color;
    ctx.fill();
  }
}

function clusterLoop(width, height) {
  clusterStep(width, height);
  clusterRender();
  clusterState.tick += 1;
  if (clusterState.tick < CLUSTER_TICKS) {
    clusterState.raf = window.requestAnimationFrame(() =>
      clusterLoop(width, height),
    );
  }
}

async function refreshClusters() {
  if (!clusterCanvas) return;
  try {
    const graph = await fetchJSON("/api/clusters");
    const w = clusterCanvas.width;
    const h = clusterCanvas.height;
    const rawNodes = graph.nodes || [];
    // Seed positions on a ring so the layout is stable and never starts
    // with coincident points (which would blow up the repulsion term).
    clusterState.nodes = rawNodes.map((node, idx) => {
      const angle = (idx / Math.max(1, rawNodes.length)) * Math.PI * 2;
      return {
        id: node.session_id,
        x: w / 2 + Math.cos(angle) * (w / 4),
        y: h / 2 + Math.sin(angle) * (h / 4),
        fx: 0,
        fy: 0,
        r: nodeRadius(node.threat_score),
        color: nodeColor(node.intent_label),
      };
    });
    clusterState.byId = {};
    for (const node of clusterState.nodes) clusterState.byId[node.id] = node;
    clusterState.edges = graph.edges || [];
    clusterState.tick = 0;
    if (clusterMeta) {
      clusterMeta.textContent = `${clusterState.nodes.length} sessions · ${clusterState.edges.length} links`;
    }
    if (clusterState.raf) window.cancelAnimationFrame(clusterState.raf);
    if (clusterState.nodes.length) {
      clusterLoop(w, h);
    } else {
      clusterRender();
    }
  } catch (err) {
    console.warn("clusters refresh failed:", err);
  }
}

function onClusterClick(ev) {
  if (!clusterCanvas) return;
  const rect = clusterCanvas.getBoundingClientRect();
  const mx = ((ev.clientX - rect.left) * clusterCanvas.width) / rect.width;
  const my = ((ev.clientY - rect.top) * clusterCanvas.height) / rect.height;
  for (const node of clusterState.nodes) {
    if (Math.hypot(node.x - mx, node.y - my) <= node.r + 4) {
      openDetail(node.id);
      return;
    }
  }
}

function pushCommandEvent(payload) {
  const li = document.createElement("li");
  const source = payload.source || "ai";
  li.className = `is-${source}`;
  li.innerHTML = `
    <div class="stream__meta">
      <code>${escapeText(payload.session_id).slice(0, 8)}</code>
      · ${escapeText(source)}
      · ${escapeText((payload.latency_ms || 0).toFixed(0))} ms
    </div>
    <div class="stream__cmd">$ ${escapeText(payload.command)}</div>
    <div class="stream__response">${escapeText(payload.response || "")}</div>
  `;
  commandStream.insertBefore(li, commandStream.firstChild);
  while (commandStream.children.length > COMMAND_STREAM_CAP) {
    commandStream.removeChild(commandStream.lastChild);
  }
}

function connectWebSocket() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${window.location.host}/ws/events`);
  setStatus("connecting…", "connecting");

  ws.addEventListener("open", () => {
    setStatus("live", "open");
    wsBackoffMs = 1000;
  });

  ws.addEventListener("message", (ev) => {
    let event;
    try {
      event = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (event.kind === "command") {
      pushCommandEvent(event.payload || {});
    } else if (event.kind === "threat") {
      refreshThreats();
    } else if (event.kind === "session_started" || event.kind === "session_ended") {
      refreshStats();
    }
  });

  ws.addEventListener("close", () => {
    setStatus("offline — reconnecting", "closed");
    setTimeout(connectWebSocket, wsBackoffMs);
    wsBackoffMs = Math.min(30000, wsBackoffMs * 2);
  });

  ws.addEventListener("error", () => {
    // The close handler will manage reconnection.
    try {
      ws.close();
    } catch {
      /* ignore */
    }
  });
}

async function boot() {
  await refreshStats();
  await refreshThreats();
  await refreshCredentials();
  await refreshClusters();
  setInterval(refreshStats, STATS_POLL_MS);
  setInterval(refreshThreats, TABLE_POLL_MS);
  setInterval(refreshCredentials, TABLE_POLL_MS);
  if (detailClose && detailPanel) {
    detailClose.addEventListener("click", () => {
      detailPanel.hidden = true;
    });
  }
  // Delegated: session links live in the threats table and inside the
  // panel's own "similar sessions" list, both rebuilt on each render.
  if (threatTable) threatTable.addEventListener("click", onSessionLinkClick);
  if (detailBody) detailBody.addEventListener("click", onSessionLinkClick);
  if (clusterCanvas) clusterCanvas.addEventListener("click", onClusterClick);
  connectWebSocket();
}

boot();
