const CASE_TABS = ["summary", "artifacts", "recovery", "carved", "correlation", "validation", "timeline"];
const SERVER_TABS = ["jobs", "reports", "audit"];
const SERVER_LEVEL = ["/api/cases", "/api/me", "/api/mode", "/api/health", "/api/admin"];
let state = { tab: "summary", filters: {}, mode: "single", token: null, me: null, caseId: null };

function storedToken() { try { return sessionStorage.getItem("af_token"); } catch (_) { return null; } }
function storeToken(t) { try { if (t) sessionStorage.setItem("af_token", t); else sessionStorage.removeItem("af_token"); } catch (_) {} }

// In server mode the per-case endpoints live under /api/cases/<id>/...; the same renderers serve both modes.
function resolve(path) {
  if (state.mode !== "server" || !state.caseId) return path;
  if (SERVER_LEVEL.some(p => path === p || path.startsWith(p + "/") || path.startsWith(p + "?"))) return path;
  return `/api/cases/${encodeURIComponent(state.caseId)}${path.slice(4)}`;
}
function authHeaders(extra) { return Object.assign({}, state.token ? { Authorization: `Bearer ${state.token}` } : {}, extra || {}); }

class AuthError extends Error {}

async function api(path, params, opts) {
  const url = new URL(resolve(path), location.origin);
  if (params) for (const [k, v] of Object.entries(params)) if (v) url.searchParams.set(k, v);
  const r = await fetch(url, Object.assign({ headers: authHeaders() }, opts || {}));
  if (r.status === 401 && state.mode === "server") throw new AuthError("unauthorised");
  if (!r.ok) {
    let detail = "";
    try { detail = (await r.json()).detail || ""; } catch (_) { detail = await r.text(); }
    throw new Error(`${r.status} ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
  }
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

function tabList() { return state.mode === "server" ? CASE_TABS.concat(SERVER_TABS) : CASE_TABS; }
function renderTabs() {
  document.getElementById("tabs").innerHTML = tabList().map(t =>
    `<button data-tab="${esc(t)}" class="${t === state.tab ? "active" : ""}">${esc(t[0].toUpperCase() + t.slice(1))}</button>`).join("");
  for (const b of document.querySelectorAll("nav button")) b.addEventListener("click", () => { state.tab = b.dataset.tab; render(); });
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
    + `<div class="card"><div class="n">${esc(r.corroborated)}</div><div class="l">Corroborated</div></div>`
    + `<div class="card"><div class="n">${esc(r.unrecovered_regions)}</div><div class="l">Unrecoverable (proven)</div></div>`;
  const rec = await api("/api/recovered", { limit: 50 });
  document.getElementById("view").innerHTML = table(
    ["ID","Table","Status","Method","Rowid","Region","Fit"], rec.records,
    [x=>esc(x.id), x=>esc(x.table_name), x=>pill(x.status), x=>esc(x.method), x=>esc(x.rowid_value ?? "unknown"), x=>esc(x.region), x=>esc(x.fit)])
    + `<div class="muted">${esc(rec.total)} recovered records — see the report for each one's full confidence explanation.</div>`;
}

async function renderCarved() {
  const c = await api("/api/carved", { limit: 50 });
  document.getElementById("cards").innerHTML = "";
  document.getElementById("view").innerHTML = `<p class="explain">A carved candidate is never confirmed evidence: it stays <b>CARVED CANDIDATE</b> whatever its confidence.</p>`
    + table(["ID","Kind","Status","Confidence","Matched","Corroborated by"], c.candidates,
      [x=>esc(x.id), x=>esc(x.kind), x=>pill(x.status), x=>esc(x.confidence||"-"), x=>esc((x.matched||"").slice(0,60)), x=>esc((x.corroborated_by||[]).length)])
    + `<div class="muted">${esc(c.total)} candidates.</div>`;
}

async function renderCorrelation() {
  const g = await api("/api/correlations", { limit: 300 });
  document.getElementById("cards").innerHTML = `<div class="card"><div class="n">${g.nodes.length}</div><div class="l">Entities</div></div>`
    + `<div class="card"><div class="n">${esc(g.total)}</div><div class="l">Edges</div></div>`;
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


// ---------------------------------------------------------------- server mode: login, cases, jobs, reports, audit
function show(id, on) { document.getElementById(id).hidden = !on; }
function setHeader() {
  document.getElementById("user-label").textContent = state.me ? `${state.me.name} (${state.me.role})` : "";
  show("logout", state.mode === "server" && !!state.me);
  show("back", state.mode === "server" && !!state.caseId);
}
function atLeast(role) { const rank = { viewer: 0, analyst: 1, admin: 2 }; return state.me && rank[state.me.role] >= rank[role]; }

function renderLogin(message) {
  document.getElementById("tabs").innerHTML = "";
  document.getElementById("cards").innerHTML = "";
  document.getElementById("case-label").textContent = "sign in";
  document.getElementById("view").innerHTML = `
    <form id="login" class="panel" autocomplete="off">
      <h3>Sign in</h3>
      <p class="muted">Paste your access token. It is kept for this browser tab only.</p>
      <input id="token" type="password" placeholder="afk_…" required autocomplete="off" spellcheck="false">
      <button type="submit">Sign in</button>
      ${message ? `<div class="err">${esc(message)}</div>` : ""}
    </form>`;
  document.getElementById("login").addEventListener("submit", async ev => {
    ev.preventDefault();
    state.token = document.getElementById("token").value.trim();
    try { state.me = await api("/api/me"); storeToken(state.token); boot(); }
    catch (e) { state.token = null; state.me = null; renderLogin(e instanceof AuthError ? "That token was not accepted." : e.message); }
  });
}

async function renderCases() {
  state.caseId = null; setHeader();
  document.getElementById("tabs").innerHTML = "";
  document.getElementById("cards").innerHTML = "";
  document.getElementById("case-label").textContent = "cases";
  const cases = await api("/api/cases");
  const form = atLeast("analyst") ? `
    <form id="new-case" class="panel">
      <h3>New case</h3>
      <div class="toolbar">
        <input id="nc-id" placeholder="case id (letters, digits, . _ -)" required pattern="[A-Za-z0-9][A-Za-z0-9_.\\-]{0,63}">
        <input id="nc-examiner" placeholder="examiner">
        <input id="nc-desc" placeholder="description" size="40">
        <button type="submit">Create</button>
      </div><div id="nc-msg"></div>
    </form>` : "";
  document.getElementById("view").innerHTML = form + table(["Case", "Description", "Examiner", "Created", "Last job"], cases,
    [c => `<a href="#" data-case="${esc(c.id)}">${esc(c.display_name)}</a>`, c => esc(c.description || ""), c => esc(c.examiner || ""), c => esc(c.created_at),
     c => c.last_job ? pill(c.last_job.status) : "-"]);
  for (const a of document.querySelectorAll("a[data-case]")) a.addEventListener("click", ev => { ev.preventDefault(); openCase(a.dataset.case); });
  const f = document.getElementById("new-case");
  if (f) f.addEventListener("submit", async ev => {
    ev.preventDefault();
    try {
      const c = await api("/api/cases", null, { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ id: document.getElementById("nc-id").value, examiner: document.getElementById("nc-examiner").value || null,
                               description: document.getElementById("nc-desc").value || null }) });
      openCase(c.id);
    } catch (e) { document.getElementById("nc-msg").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  });
}

function openCase(id) { state.caseId = id; state.tab = "jobs"; setHeader(); render(); }

async function renderJobs() {
  document.getElementById("cards").innerHTML = "";
  const [jobs, uploads] = await Promise.all([api("/api/jobs"), api("/api/uploads")]);
  const canWrite = atLeast("analyst");
  const upForm = canWrite ? `
    <div class="panel"><h3>Add evidence</h3>
      <div class="toolbar"><input type="file" id="up-file"><button id="up-go">Upload</button><progress id="up-bar" value="0" max="100" hidden></progress></div>
      <div id="up-msg" class="muted">Disk images (raw / sparse / E01), directory archives (.zip, .tar.gz) or a SQLite database. Stored read-only; hashed while uploading.</div>
    </div>` : "";
  document.getElementById("view").innerHTML = upForm +
    "<h3>Evidence uploads</h3>" + table(["Name", "Size", "SHA-256", "By", "Uploaded", "Action"], uploads,
      [u => esc(u.name), u => esc(u.size.toLocaleString()), u => `<code>${esc(u.sha256.slice(0, 16))}…</code>`, u => esc(u.uploaded_by), u => esc(u.uploaded_at),
       u => canWrite ? `<button data-analyze="${esc(u.id)}">Analyse</button>` : ""]) +
    `<h3>Jobs</h3><div class="toolbar">${canWrite ? '<button id="job-report">Regenerate report</button>' : ""}<button id="job-refresh">Refresh</button></div>` +
    table(["Job", "Kind", "Status", "Started", "Finished", "Reason", "Action"], jobs,
      [j => `<code>${esc(j.id.slice(0, 8))}</code>`, j => esc(j.kind), j => pill(j.status), j => esc(j.started_at || "-"), j => esc(j.finished_at || "-"),
       j => esc(j.reason || ""), j => `<button data-log="${esc(j.id)}">Log</button>` + (canWrite && (j.status === "running" || j.status === "queued") ? ` <button data-cancel="${esc(j.id)}">Cancel</button>` : "")]) +
    '<pre id="log" class="log" hidden></pre>';
  const refresh = () => render();
  document.getElementById("job-refresh").addEventListener("click", refresh);
  if (jobs.some(j => j.status === "running" || j.status === "queued")) { clearTimeout(state.poll); state.poll = setTimeout(() => { if (state.tab === "jobs") refresh(); }, 3000); }
  for (const b of document.querySelectorAll("button[data-log]")) b.addEventListener("click", async () => {
    const j = await api(`/api/jobs/${encodeURIComponent(b.dataset.log)}`, { log: "1" });
    const pre = document.getElementById("log"); pre.hidden = false; pre.textContent = j.log_tail || "(no output yet)";
  });
  for (const b of document.querySelectorAll("button[data-cancel]")) b.addEventListener("click", async () => {
    await api(`/api/jobs/${encodeURIComponent(b.dataset.cancel)}/cancel`, null, { method: "POST" }); refresh();
  });
  for (const b of document.querySelectorAll("button[data-analyze]")) b.addEventListener("click", async () => {
    await api("/api/jobs", null, { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ kind: "analyze", upload_id: b.dataset.analyze }) }); refresh();
  });
  const rep = document.getElementById("job-report");
  if (rep) rep.addEventListener("click", async () => {
    await api("/api/jobs", null, { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ kind: "report" }) }); refresh();
  });
  const go = document.getElementById("up-go");
  if (go) go.addEventListener("click", () => {
    const file = document.getElementById("up-file").files[0];
    if (!file) return;
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", `/api/cases/${encodeURIComponent(state.caseId)}/uploads?filename=${encodeURIComponent(file.name)}`);
    xhr.setRequestHeader("Authorization", `Bearer ${state.token}`);
    const bar = document.getElementById("up-bar"); bar.hidden = false;
    xhr.upload.onprogress = e => { if (e.lengthComputable) bar.value = Math.round(100 * e.loaded / e.total); };
    xhr.onload = () => {
      if (xhr.status === 201) { render(); return; }
      let msg = xhr.responseText; try { msg = JSON.parse(msg).detail; } catch (_) {}
      document.getElementById("up-msg").innerHTML = `<div class="err">${esc(`${xhr.status} ${msg}`)}</div>`;
    };
    xhr.onerror = () => { document.getElementById("up-msg").innerHTML = '<div class="err">Upload failed (network).</div>'; };
    xhr.send(file);
  });
}

async function download(report, file) {
  const r = await fetch(`/api/cases/${encodeURIComponent(state.caseId)}/reports/${encodeURIComponent(report)}/${file.split("/").map(encodeURIComponent).join("/")}`, { headers: authHeaders() });
  if (!r.ok) { alert(`Download failed: ${r.status}`); return; }
  const a = document.createElement("a");
  a.href = URL.createObjectURL(await r.blob()); a.download = file.split("/").pop();
  document.body.appendChild(a); a.click(); a.remove();
}

async function renderReports() {
  document.getElementById("cards").innerHTML = "";
  const reports = await api("/api/reports");
  document.getElementById("view").innerHTML = `<p class="explain">Reports download as files and are never rendered inside this page. A signed report can be verified offline with <code>android-forensics verify-report</code>.</p>` +
    table(["Report", "Signed", "Files"], reports,
      [r => esc(r.name), r => r.signed ? pill("VALID") : "unsigned",
       r => r.files.map(f => `<button data-rep="${esc(r.name)}" data-file="${esc(f)}">${esc(f)}</button>`).join(" ")]);
  for (const b of document.querySelectorAll("button[data-rep]")) b.addEventListener("click", () => download(b.dataset.rep, b.dataset.file));
}

async function renderAudit() {
  document.getElementById("cards").innerHTML = "";
  const a = await api("/api/audit");
  const problem = a.problem ? " — " + a.problem : "";
  document.getElementById("view").innerHTML = `<p class="explain">Command audit log for this case: ${pill(a.intact ? "VALID" : "INVALID")} ${esc(a.entries)} entries, chain head <code>${esc(a.head)}</code>${esc(problem)}</p>` +
    table(["#", "Time", "User", "Command", "Outcome"], a.tail.slice().reverse(),
      [e => esc(e.seq), e => esc(e.ts), e => esc(`${e.user}@${e.host}`), e => esc(e.command), e => esc(e.outcome)]);
}

const RENDERERS = { summary: renderSummary, artifacts: renderArtifacts, recovery: renderRecovery, carved: renderCarved,
                    correlation: renderCorrelation, validation: renderValidation, timeline: renderTimeline,
                    jobs: renderJobs, reports: renderReports, audit: renderAudit };

async function render() {
  setHeader();
  if (state.mode === "server" && !state.caseId) { try { await renderCases(); } catch (e) { fail(e); } return; }
  renderTabs();
  try { await RENDERERS[state.tab](); } catch (e) { fail(e); }
}
function fail(e) {
  if (e instanceof AuthError) { state.token = null; state.me = null; storeToken(null); renderLogin("Your session ended. Sign in again."); return; }
  document.getElementById("view").innerHTML = `<div class="err">Failed to load: ${esc(e.message)}</div>`;
}

async function boot() {
  try { state.mode = (await api("/api/mode")).mode; } catch (_) { state.mode = "single"; }
  document.getElementById("logout").addEventListener("click", () => { state.token = null; state.me = null; state.caseId = null; storeToken(null); boot(); }, { once: true });
  document.getElementById("back").addEventListener("click", () => { state.caseId = null; render(); }, { once: true });
  if (state.mode === "server") {
    state.token = state.token || storedToken();
    if (!state.token) { setHeader(); renderLogin(); return; }
    try { state.me = await api("/api/me"); } catch (e) { fail(e); return; }
  }
  render();
}
boot();
