import { FormEvent, Suspense, lazy, useCallback, useEffect, useState } from "react";

const InvestigationTools = lazy(() => import("./investigation-tools"));

type User = { username: string; role: string; badge_number: string };
type CaseRecord = {
  id: number;
  case_number: string;
  title: string;
  description: string;
  priority: "LOW" | "MEDIUM" | "HIGH";
  status: "OPEN" | "UNDER_REVIEW" | "CLOSED";
  risk_score: number;
  created_at: string;
};
type AuditEntry = {
  id: number;
  timestamp_iso: string;
  actor: string;
  action: string;
  resource: string;
  entry_hash: string;
};
type EvidenceRecord = {
  id: number;
  case_id: number;
  original_filename: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  uploaded_by: string;
  created_at: string;
};

const roleNames: Record<string, string> = {
  INVESTIGATOR: "Investigator",
  REVIEWER: "Reviewer",
  ADMIN: "Admin",
};

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem("sentinel-token") ?? "");
  const [user, setUser] = useState<User | null>(null);
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [loginName, setLoginName] = useState("investigator_alice");
  const [loginPassword, setLoginPassword] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState<CaseRecord["priority"]>("MEDIUM");
  const [workspace, setWorkspace] = useState<"cases" | "evidence" | "analysis" | "network" | "review" | "reports">("cases");
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<number | null>(null);
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [confirmedSynthetic, setConfirmedSynthetic] = useState(false);

  const api = useCallback(
    async <T,>(path: string, options: RequestInit = {}): Promise<T> => {
      const response = await fetch(path, {
        ...options,
        headers: {
          ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...options.headers,
        },
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(typeof body.detail === "string" ? body.detail : `Request failed (${response.status})`);
      }
      return body as T;
    },
    [token],
  );

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const [me, caseRows, auditRows] = await Promise.all([
        api<User>("/api/v1/auth/me"),
        api<CaseRecord[]>("/api/v1/cases"),
        api<AuditEntry[]>("/api/v1/audit/logs"),
      ]);
      setUser(me);
      setCases(caseRows);
      setAudit(auditRows.slice(0, 6));
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load the workspace.");
    }
  }, [api, token]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const selectedCase = cases.find((record) => record.id === selectedCaseId) ?? null;

  const refreshEvidence = useCallback(async () => {
    if (selectedCaseId === null) {
      setEvidence([]);
      setSelectedEvidenceId(null);
      return;
    }
    try {
      const items = await api<EvidenceRecord[]>(`/api/v1/cases/${selectedCaseId}/evidence`);
      setEvidence(items);
      setSelectedEvidenceId((current) =>
        current !== null && items.some((item) => item.id === current) ? current : items[0]?.id ?? null,
      );
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load evidence.");
    }
  }, [api, selectedCaseId]);

  useEffect(() => {
    void refreshEvidence();
  }, [refreshEvidence]);

  async function login(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await api<{ access_token: string }>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ username: loginName, password: loginPassword }),
      });
      localStorage.setItem("sentinel-token", result.access_token);
      setToken(result.access_token);
      setLoginPassword("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  async function createCase(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api<CaseRecord>("/api/v1/cases", {
        method: "POST",
        body: JSON.stringify({ title, description, priority }),
      });
      setTitle("");
      setDescription("");
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Case could not be created.");
    } finally {
      setBusy(false);
    }
  }

  async function changeStatus(record: CaseRecord, status: CaseRecord["status"]) {
    setBusy(true);
    setError("");
    try {
      await api<CaseRecord>(`/api/v1/cases/${record.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Case could not be updated.");
    } finally {
      setBusy(false);
    }
  }

  async function uploadEvidence(file: File) {
    if (selectedCaseId === null) return;
    if (!confirmedSynthetic) {
      setError("Confirm that this is synthetic or harmless benign test data before uploading.");
      return;
    }
    setUploading(true);
    setError("");
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("synthetic_data_confirmed", "true");
      const response = await fetch(`/api/v1/cases/${selectedCaseId}/evidence`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(typeof body.detail === "string" ? body.detail : `Upload failed (${response.status})`);
      }
      setWorkspace("evidence");
      await refreshEvidence();
      setSelectedEvidenceId((body as EvidenceRecord).id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Upload failed.");
    } finally {
      setUploading(false);
    }
  }

  async function downloadEvidence(record: EvidenceRecord) {
    setError("");
    try {
      const response = await fetch(`/api/v1/evidence/${record.id}/download`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(typeof body.detail === "string" ? body.detail : `Download failed (${response.status})`);
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = record.original_filename;
      link.click();
      URL.revokeObjectURL(url);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Download failed.");
    }
  }

  function logout() {
    localStorage.removeItem("sentinel-token");
    setToken("");
    setUser(null);
    setCases([]);
    setAudit([]);
  }

  if (!token || !user) {
    return (
      <main className="login-shell">
        <div className="login-card">
          <Brand />
          <p className="eyebrow">SECURE INVESTIGATION WORKSPACE</p>
          <h1>Sign in to Sentinel-X</h1>
          <p className="muted">Access is role-based. Every finding stays under investigator review.</p>
          <form onSubmit={login} className="stack">
            <label>Username<input value={loginName} onChange={(event) => setLoginName(event.target.value)} autoComplete="username" required /></label>
            <label>Password<input type="password" value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} autoComplete="current-password" required /></label>
            {error && <p className="error" role="alert">{error}</p>}
            <button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
          </form>
          <p className="hint">Local demo: investigator_alice / Password123!</p>
          <HumanNotice />
        </div>
      </main>
    );
  }

  const highPriority = cases.filter((item) => item.priority === "HIGH").length;
  const awaitingReview = cases.filter((item) => item.status === "UNDER_REVIEW").length;
  const workspaceTitles = {
    cases: ["Case workspace", "Investigate synthetic cases and move into evidence intake when ready."],
    evidence: ["Evidence lab", "Upload, inspect provenance, and organize case evidence in one focused workspace."],
    analysis: ["Pattern analysis", "Inspect explainable signals from investigator-uploaded evidence."],
    network: ["Correlation network", "Explore possible relationships across synthetic case evidence."],
    review: ["Human review", "Review signal details and record a human decision."],
    reports: ["Evidence reports", "Create a case PDF with provenance, analysis, and review history."],
  } as const;

  return (
    <main className="app-shell">
      <header className="topbar">
        <Brand />
        <div className="user-menu"><span>{user.badge_number} · {roleNames[user.role] ?? user.role}</span><button className="secondary compact" onClick={logout}>Sign out</button></div>
      </header>
      <HumanNotice />
      <section className="welcome">
        <div><p className="eyebrow">INVESTIGATION WORKBENCH</p><h1>{workspaceTitles[workspace][0]}</h1><p className="muted">{workspaceTitles[workspace][1]}</p></div>
        <span className="date-chip">Local evidence only</span>
      </section>
      <nav className="workspace-nav" aria-label="Investigation workspaces">
        <button className={workspace === "cases" ? "nav-tab active" : "nav-tab"} onClick={() => setWorkspace("cases")}>Case overview</button>
        <button className={workspace === "evidence" ? "nav-tab active" : "nav-tab"} onClick={() => setWorkspace("evidence")}>Evidence lab <span>{evidence.length}</span></button>
        <button className={workspace === "analysis" ? "nav-tab active" : "nav-tab"} onClick={() => setWorkspace("analysis")}>Analysis</button>
        <button className={workspace === "network" ? "nav-tab active" : "nav-tab"} onClick={() => setWorkspace("network")}>Network</button>
        {(user.role === "REVIEWER" || user.role === "ADMIN") && <button className={workspace === "review" ? "nav-tab active" : "nav-tab"} onClick={() => setWorkspace("review")}>Review</button>}
        <button className={workspace === "reports" ? "nav-tab active" : "nav-tab"} onClick={() => setWorkspace("reports")}>Reports</button>
        <span className="future-tool">Synthetic-data mode</span>
      </nav>
      {error && <p className="error banner-error" role="alert">{error}</p>}
      {workspace === "cases" && <section className="metrics">
        <Metric label="Accessible cases" value={cases.length.toString()} detail="Assigned to your role" />
        <Metric label="High priority" value={highPriority.toString()} detail="Investigator-defined" />
        <Metric label="Under review" value={awaitingReview.toString()} detail="Human review required" />
      </section>
      }
      {workspace === "cases" ? <>
      <div className="content-grid">
        <section className="panel cases-panel">
          <div className="section-heading"><div><p className="eyebrow">ACTIVE WORK</p><h2>Cases</h2></div><span className="counter">{cases.length}</span></div>
          {cases.length === 0 ? <div className="empty"><strong>No cases yet</strong><p>Create a synthetic test case to begin. Upload and analysis arrive in later phases.</p></div> :
            <div className="case-list">{cases.map((record) => <article className="case-card" key={record.id}>
              <div className="case-meta"><span>{record.case_number}</span><span className={`pill priority-${record.priority.toLowerCase()}`}>{record.priority}</span></div>
              <h3>{record.title}</h3><p className="case-description">{record.description || "No description provided."}</p>
              <div className="case-footer"><span className={`pill status-${record.status.toLowerCase()}`}>{record.status.replace("_", " ")}</span><label className="status-control">Status<select value={record.status} disabled={busy || user.role === "REVIEWER"} onChange={(event) => void changeStatus(record, event.target.value as CaseRecord["status"])}><option value="OPEN">Open</option><option value="UNDER_REVIEW">Under review</option><option value="CLOSED">Closed</option></select></label></div>
            </article>)}</div>}
        </section>
        <aside className="side-column">
          {user.role !== "REVIEWER" && <section className="panel">
            <div className="section-heading"><div><p className="eyebrow">CASE MANAGEMENT</p><h2>New case</h2></div></div>
            <form onSubmit={createCase} className="stack">
              <label>Case title<input value={title} onChange={(event) => setTitle(event.target.value)} maxLength={200} required placeholder="Synthetic investigation" /></label>
              <label>Summary<textarea value={description} onChange={(event) => setDescription(event.target.value)} maxLength={10000} rows={3} placeholder="Use fabricated, harmless test details only." /></label>
              <label>Priority<select value={priority} onChange={(event) => setPriority(event.target.value as CaseRecord["priority"])}><option>LOW</option><option>MEDIUM</option><option>HIGH</option></select></label>
              <button disabled={busy}>Create case</button>
            </form>
          </section>}
          <section className="panel audit-panel">
            <div className="section-heading"><div><p className="eyebrow">CHAIN OF CUSTODY</p><h2>Recent audit events</h2></div></div>
            {audit.length === 0 ? <p className="muted">No audit events yet.</p> : <div className="audit-list">{audit.map((entry) => <div className="audit-entry" key={entry.id}><div><strong>{entry.action.replace(/_/g, " ")}</strong><span>{entry.actor} · {new Date(entry.timestamp_iso).toLocaleString()}</span></div><code title={entry.entry_hash}>{entry.entry_hash.slice(0, 12)}…</code></div>)}</div>}
            <button className="secondary verify-button" onClick={async () => { try { const result = await api<{is_valid:boolean;message:string}>("/api/v1/audit/verify", {method:"POST"}); setError(result.message); await refresh(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Audit verification failed."); } }}>{busy ? "Working…" : "Verify audit chain"}</button>
          </section>
        </aside>
      </div>
      </> : workspace === "evidence" ? <section className="evidence-workbench">
        <aside className="panel evidence-cases">
          <div className="section-heading"><div><p className="eyebrow">SELECT A MATTER</p><h2>Case files</h2></div><span className="counter">{cases.length}</span></div>
          {cases.length === 0 ? <div className="empty"><strong>No accessible cases</strong><p>Create a case before adding evidence.</p></div> : <div className="case-list">{cases.map((record) => <button key={record.id} className={`case-picker${selectedCaseId === record.id ? " selected" : ""}`} onClick={() => { setSelectedCaseId(record.id); setConfirmedSynthetic(false); }}><span className="case-meta">{record.case_number}<span>{record.status.replace("_", " ")}</span></span><strong>{record.title}</strong><small>{record.priority} priority</small></button>)}</div>}
        </aside>
        <section className="panel evidence-main">
          {selectedCase ? <>
            <div className="section-heading"><div><p className="eyebrow">{selectedCase.case_number}</p><h2>{selectedCase.title}</h2><p className="muted">{selectedCase.description || "No case summary."}</p></div><span className="counter">{evidence.length} files</span></div>
            {user.role !== "REVIEWER" && <>
              <label className="synthetic-confirm"><input type="checkbox" checked={confirmedSynthetic} onChange={(event) => setConfirmedSynthetic(event.target.checked)} /><span>I confirm this is fabricated or harmless benign test data. No real abuse material or personal evidence is uploaded.</span></label>
              <label className={`drop-zone${dragging ? " dragging" : ""}${!confirmedSynthetic ? " disabled" : ""}`} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); const file = event.dataTransfer.files[0]; if (file) void uploadEvidence(file); }}>
                <span className="upload-mark">↑</span><strong>{uploading ? "Securing evidence…" : "Drop a synthetic evidence file here"}</strong><small>or click to choose · PNG, JPEG, WebP, WAV, MP3, JSON · max 15 MiB</small><small>SHA-256 is calculated on upload; originals stay private and are never analyzed automatically.</small>
                <input type="file" accept=".png,.jpg,.jpeg,.webp,.wav,.mp3,.json" disabled={uploading || !confirmedSynthetic} onChange={(event) => { const file = event.target.files?.[0]; if (file) void uploadEvidence(file); event.currentTarget.value = ""; }} />
              </label>
            </>}
            <div className="evidence-content">
              <div className="evidence-list">
                <div className="subheading"><strong>Evidence ledger</strong><span>Originals · SHA-256</span></div>
                {evidence.length === 0 ? <div className="empty"><strong>Nothing attached yet</strong><p>Add a harmless synthetic file to start a documented evidence trail.</p></div> : evidence.map((item) => <button key={item.id} className={`evidence-row${selectedEvidenceId === item.id ? " selected" : ""}`} onClick={() => setSelectedEvidenceId(item.id)}><span className="file-icon">{item.media_type.startsWith("image/") ? "IMG" : item.media_type.startsWith("audio/") ? "AUD" : "JSON"}</span><span className="evidence-name"><strong>{item.original_filename}</strong><small>{formatBytes(item.size_bytes)} · {new Date(item.created_at).toLocaleString()}</small></span><span className="evidence-state">HASHED</span></button>)}
              </div>
              <div className="evidence-detail">
                {evidence.find((item) => item.id === selectedEvidenceId) ? (() => { const item = evidence.find((entry) => entry.id === selectedEvidenceId)!; return <>
                  <div className="detail-top"><span className="eyebrow">CHAIN OF CUSTODY</span><span className="pill status-open">ORIGINAL PRESERVED</span></div>
                  <h3>{item.original_filename}</h3><p className="muted">This file is stored as private evidence. Access is logged; downloaded files are served as attachments.</p>
                  <dl className="evidence-facts"><div><dt>SHA-256</dt><dd className="hash-value">{item.sha256}</dd></div><div><dt>Media type</dt><dd>{item.media_type}</dd></div><div><dt>File size</dt><dd>{formatBytes(item.size_bytes)}</dd></div><div><dt>Uploaded by</dt><dd>{item.uploaded_by}</dd></div><div><dt>Added</dt><dd>{new Date(item.created_at).toLocaleString()}</dd></div></dl>
                  <button className="secondary download-button" onClick={() => void downloadEvidence(item)}>Download original · log access</button>
                </>; })() : <div className="detail-empty"><span>⌕</span><strong>Select an evidence item</strong><p>Its hash and custody details will appear here.</p></div>}
              </div>
            </div>
            <div className="analysis-next"><span className="notice-icon">i</span><span><strong>Analysis tools are not enabled in this phase.</strong><small>Next: explainable OCR, duplicate detection, and synthetic language-pattern cues. No age estimation or automatic decisions.</small></span></div>
          </> : <div className="empty select-case"><strong>Select a case to open its evidence lab</strong><p>Evidence is kept in case context and every upload is added to the hash-chained audit log.</p></div>}
        </section>
      </section> : <Suspense fallback={<section className="panel empty"><strong>Opening investigation tools…</strong></section>}><InvestigationTools
        mode={workspace}
        api={api}
        token={token}
        role={user.role}
        cases={cases}
        selectedCaseId={selectedCaseId}
        onSelectCase={setSelectedCaseId}
        onError={setError}
        onRefresh={refresh}
      /></Suspense>}
      <footer>Sentinel-X · Synthetic-data MVP · Analysis assists investigators; it never makes decisions.</footer>
    </main>
  );
}

function Brand() {
  return <div className="brand"><span className="brand-mark">S</span><span>SENTINEL<span className="brand-accent">-X</span><small>INVESTIGATION INTELLIGENCE</small></span></div>;
}

function HumanNotice() {
  return <div className="human-notice"><span className="notice-icon">!</span><span><strong>Human-in-the-loop: no autonomous actions</strong><small>Sentinel-X only analyzes evidence investigators upload or import. Every finding requires investigator confirmation.</small></span></div>;
}

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <article className="metric-card"><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>;
}

function formatBytes(size: number): string {
  return size < 1024 * 1024 ? `${(size / 1024).toFixed(1)} KB` : `${(size / (1024 * 1024)).toFixed(2)} MB`;
}
