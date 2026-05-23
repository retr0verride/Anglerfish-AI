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

function escapeText(value) {
  if (value === null || value === undefined) return "";
  return String(value);
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
        <td><code>${escapeText(t.session_id).slice(0, 8)}</code></td>
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
  connectWebSocket();
}

boot();
