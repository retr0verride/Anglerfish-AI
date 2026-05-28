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
// fields executes in the operator's authenticated session. There is no
// CSP backstop, so this function is the boundary.
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
  connectWebSocket();
}

boot();
