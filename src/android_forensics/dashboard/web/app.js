const TABS = ["summary", "artifacts", "recovery", "carved", "correlation", "validation", "timeline"];
let state = { tab: "summary", filters: {} };

async function api(path, params) {
  const url = new URL(path, location.origin);
  if (params) for (const [k, v] of Object.entries(params)) if (v) url.searchParams.set(k, v);
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}
// Every value that originates in evidence goes through esc() before it reaches innerHTML.
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function pill(text) {
  const cls = text === 'CARVED CANDIDATE' ? 'candidate' : String(text ?? "").replace(/[^A-Za-z_-]/g, "");
  return `<span class="pill ${cls}">${esc(text)}</span>`;
}
function table(cols, rows, renderers) {
  const head = cols.map(c => `<th>${c}</th>`).join("");
  const body = rows.map(r => `<tr>${cols.map((c, i) => `<td>${(renderers && renderers[i]) ? renderers[i](r) : esc(r[c.toLowerCase().replace(/ /g,"_")])}</td>`).join("")}</tr>`).join("");
  return `<table><thead><tr>${head}</tr></thead><tbody>${body || `<tr><td colspan="${cols.length}" class="muted">No rows.</td></tr>`}</tbody></table>`;
}

function renderTabs() {
  document.getElementById("tabs").innerHTML = TABS.map(t =>
    `<button data-tab="${t}" class="${t === state.tab ? "active" : ""}">${t[0].toUpperCase() + t.slice(1)}</button>`).join("");
  for (const b of document.querySelectorAll("nav button")) b.onclick = () => { state.tab = b.dataset.tab; render(); };
}

async function renderSummary() {
  const s = await api("/api/summary");
  document.getElementById("case-label").textContent = `${s.case.name} — ${s.case.id.slice(0, 8)} — ${s.case.layout || "not scanned"}`;
  const c = s.counts;
  document.getElementById("cards").innerHTML = [
    ["Files", c.files], ["Databases", c.databases], ["Active artifacts", c.active_artifacts],
    ["Recovered records", c.recovered_records], ["Reconstructed", c.recovered_artifacts],
    ["Carved candidates", c.carved_candidates], ["Correlation edges", c.correlation_edges],
    ["Validation results", c.validation_results],
  ].map(([l, n]) => `<div class="card"><div class="n">${esc(n.toLocaleString())}</div><div class="l">${esc(l)}</div></div>`).join("");
  document.getElementById("view").innerHTML = "<h3>Analysis runs</h3>" + table(
    ["Stage", "Status", "Started", "Finished"], s.runs,
    [r => esc(r.stage), r => pill(r.status), r => esc(r.started_at), r => esc(r.finished_at || "-")]);
}

async function renderArtifacts() {
  const f = state.filters;
  const d = await api("/api/artifacts", { type: f.type, status: f.status, app: f.app, limit: 50 });
  document.getElementById("cards").innerHTML = "";
  document.getElementById("view").innerHTML = `
    <div class="toolbar">
      <select id="f-type"><option value="">All types</option>${["sms","call","contact","browser_visit","browser_download","generic_record"].map(t=>`<option ${f.type===t?"selected":""}>${t}</option>`).join("")}</select>
      <select id="f-status"><option value="">All statuses</option>${["ACTIVE","RECOVERED","PARTIAL","CORRUPTED"].map(t=>`<option ${f.status===t?"selected":""}>${t}</option>`).join("")}</select>
    </div>
    ${table(["ID","Type","Status","Confidence","Timestamp","Summary"], d.artifacts,
      [r=>esc(r.id), r=>esc(r.artifact_type), r=>pill(r.status), r=>esc(r.confidence||"-"), r=>esc(r.ts_utc||"-"), r=>esc((r.summary||"").slice(0,90))])}
    <div class="muted">${d.total.toLocaleString()} total (showing ${d.artifacts.length})</div>`;
  document.getElementById("f-type").onchange = e => { state.filters.type = e.target.value; renderArtifacts(); };
  document.getElementById("f-status").onchange = e => { state.filters.status = e.target.value; renderArtifacts(); };
}

async function renderRecovery() {
  const r = await api("/api/recovery");
  document.getElementById("cards").innerHTML = Object.entries(r.by_status).map(([k,n]) =>
    `<div class="card"><div class="n">${esc(n)}</div><div class="l">${esc(k)}</div></div>`).join("")
    + `<div class="card"><div class="n">${r.corroborated}</div><div class="l">Corroborated</div></div>`
    + `<div class="card"><div class="n">${r.unrecovered_regions}</div><div class="l">Unrecoverable (proven)</div></div>`;
  const rec = await api("/api/recovered", { limit: 50 });
  document.getElementById("view").innerHTML = table(
    ["ID","Table","Status","Method","Rowid","Region","Fit"], rec.records,
    [x=>esc(x.id), x=>esc(x.table_name), x=>pill(x.status), x=>esc(x.method), x=>esc(x.rowid_value ?? "unknown"), x=>esc(x.region), x=>esc(x.fit)])
    + `<div class="muted">${rec.total} recovered records — see the report for each one's full confidence explanation.</div>`;
}

async function renderCarved() {
  const c = await api("/api/carved", { limit: 50 });
  document.getElementById("cards").innerHTML = "";
  document.getElementById("view").innerHTML = `<p class="explain">A carved candidate is never confirmed evidence: it stays <b>CARVED CANDIDATE</b> whatever its confidence.</p>`
    + table(["ID","Kind","Status","Confidence","Matched","Corroborated by"], c.candidates,
      [x=>esc(x.id), x=>esc(x.kind), x=>pill(x.status), x=>esc(x.confidence||"-"), x=>esc((x.matched||"").slice(0,60)), x=>esc((x.corroborated_by||[]).length)])
    + `<div class="muted">${c.total} candidates.</div>`;
}

async function renderCorrelation() {
  const g = await api("/api/correlations", { limit: 300 });
  document.getElementById("cards").innerHTML = `<div class="card"><div class="n">${g.nodes.length}</div><div class="l">Entities</div></div>`
    + `<div class="card"><div class="n">${g.total}</div><div class="l">Edges</div></div>`;
  document.getElementById("view").innerHTML = table(
    ["Source","Relation","Target","Explanation"], g.edges,
    [e=>esc(`${e.source_kind}:${e.source_ref}`), e=>esc(e.relation), e=>esc(`${e.target_kind}:${e.target_ref}`), e=>esc(e.explanation)]);
}

async function renderValidation() {
  const v = await api("/api/validation", { limit: 100 });
  document.getElementById("cards").innerHTML = Object.entries(v.by_status).map(([k,n]) =>
    `<div class="card"><div class="n">${esc(n)}</div><div class="l">${esc(k)}</div></div>`).join("");
  document.getElementById("view").innerHTML = table(
    ["Status","Check","Target","Detail"], v.results,
    [r=>pill(r.status), r=>esc(r.check_name), r=>esc((r.target_label||"").slice(0,50)), r=>esc((r.detail||"").slice(0,140))]);
}

async function renderTimeline() {
  const t = await api("/api/timeline", { limit: 80 });
  document.getElementById("cards").innerHTML = "";
  document.getElementById("view").innerHTML = table(
    ["Timestamp","Kind","Type","Status","Event"], t.events,
    [e=>esc(e.ts_utc), e=>esc(e.event_kind), e=>esc(e.artifact_type||"file"), e=>e.status?pill(e.status):"-", e=>esc((e.event||"").slice(0,90))])
    + `<div class="muted">${t.total.toLocaleString()} events.</div>`;
}

const RENDERERS = { summary: renderSummary, artifacts: renderArtifacts, recovery: renderRecovery, carved: renderCarved,
                    correlation: renderCorrelation, validation: renderValidation, timeline: renderTimeline };

async function render() {
  renderTabs();
  try {
    await RENDERERS[state.tab]();
  } catch (e) {
    document.getElementById("view").innerHTML = `<div class="err">Failed to load: ${esc(e.message)}</div>`;
  }
}
render();
