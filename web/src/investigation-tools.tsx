import cytoscape from "cytoscape";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from "chart.js";
import { Line } from "react-chartjs-2";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

type CaseRecord = { id: number; case_number: string; title: string };
type EvidenceRecord = {
  id: number;
  original_filename: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
};
type VisualSignals = {
  status: string;
  width?: number;
  height?: number;
  mode?: string;
  perceptual_hash?: string;
  duplicate_candidates?: Array<{ analysis_id: number; case_id: number; distance: number; match: string }>;
  scope?: string;
  ocr?: { status: string; text?: string; message: string };
};
type LanguageSignals = {
  status: string;
  token_count?: number;
  message_count?: number;
  cue_category_count?: number;
  language_cue_categories?: Array<{ category: string; cue_count: number }>;
  keywords?: Array<{ term: string; count: number }>;
  entities?: Record<string, string[]>;
  review_note?: string;
};
type BehaviorSignals = {
  status: string;
  message_count?: number;
  distinct_senders?: number;
  messages_per_hour?: number | null;
  source?: string;
  repeated_senders?: Array<{ sender: string; message_count: number }>;
};
type AnalysisSignals = {
  evidence: { id: number; filename: string; sha256: string; media_type: string; size_bytes: number };
  visual?: VisualSignals;
  language?: LanguageSignals;
  behavior?: BehaviorSignals;
  known_hash: { match: string | null; source: string };
  voice?: { status: string; message: string };
};
type AnalysisRecord = {
  id: number;
  evidence_id: number;
  created_at: string;
  signals: AnalysisSignals;
};
type ImagePreview = { evidenceId: number; url: string; error: string | null };
type Assessment = {
  id: number;
  case_id: number;
  score: number;
  tier: string;
  created_at: string;
  explanation: string;
  components: Record<string, { weight: number; observed: number; contribution: number }>;
};
type GraphData = {
  nodes: Array<{ data: { id: string; label: string; kind: string; title?: string } }>;
  edges: Array<{ data: { id: string; source: string; target: string; label: string; status: string; link_id: number; reason: string } }>;
};
type QueueItem = {
  assessment_id: number;
  case_id: number;
  case_number: string;
  case_title: string;
  score: number;
  tier: string;
  explanation: { components: Assessment["components"]; explanation: string };
  signal_runs: AnalysisRecord[];
  created_at: string;
};
type Mode = "analysis" | "network" | "review" | "reports";
type Api = <T,>(path: string, options?: RequestInit) => Promise<T>;

type Props = {
  mode: Mode;
  api: Api;
  token: string;
  role: string;
  cases: CaseRecord[];
  selectedCaseId: number | null;
  onSelectCase: (id: number) => void;
  onError: (message: string) => void;
  onRefresh: () => Promise<void>;
};

const tierClass = (tier: string) => `tier tier-${tier.toLowerCase()}`;
const tierLabel = (tier: string) => tier === "AMBIGUOUS" ? "NEEDS REVIEW" : tier;

export default function InvestigationTools({
  mode,
  api,
  token,
  role,
  cases,
  selectedCaseId,
  onSelectCase,
  onError,
  onRefresh,
}: Props) {
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [analyses, setAnalyses] = useState<AnalysisRecord[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [graph, setGraph] = useState<GraphData>({ nodes: [], edges: [] });
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [selectedEdgeId, setSelectedEdgeId] = useState<number | null>(null);
  const [imagePreview, setImagePreview] = useState<ImagePreview | null>(null);
  const graphHost = useRef<HTMLDivElement>(null);
  const selectedCase = cases.find((item) => item.id === selectedCaseId) ?? null;

  const loadCaseData = useCallback(async () => {
    if (selectedCaseId === null) {
      setEvidence([]);
      setAnalyses([]);
      setAssessments([]);
      return;
    }
    try {
      const [evidenceRows, analysisRows, assessmentRows] = await Promise.all([
        api<EvidenceRecord[]>(`/api/v1/cases/${selectedCaseId}/evidence`),
        api<AnalysisRecord[]>(`/api/v1/cases/${selectedCaseId}/analysis`),
        api<Assessment[]>(`/api/v1/cases/${selectedCaseId}/fusion`),
      ]);
      setEvidence(evidenceRows);
      setAnalyses(analysisRows);
      setAssessments(assessmentRows);
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Could not load analysis workspace.");
    }
  }, [api, onError, selectedCaseId]);

  const loadGraph = useCallback(async () => {
    try {
      setGraph(await api<GraphData>("/api/v1/graph"));
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Could not load the correlation graph.");
    }
  }, [api, onError]);

  const loadQueue = useCallback(async () => {
    try {
      setQueue(await api<QueueItem[]>("/api/v1/review-queue"));
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Could not load the review queue.");
    }
  }, [api, onError]);

  useEffect(() => {
    if (mode === "analysis" || mode === "reports") void loadCaseData();
    if (mode === "network") void loadGraph();
    if (mode === "review" && (role === "REVIEWER" || role === "ADMIN")) void loadQueue();
  }, [mode, role, loadCaseData, loadGraph, loadQueue]);

  const analyze = async (item: EvidenceRecord) => {
    if (selectedCaseId === null) return;
    setBusyId(item.id);
    try {
      const result = await api<AnalysisRecord>(
        `/api/v1/cases/${selectedCaseId}/evidence/${item.id}/analyze`,
        { method: "POST" },
      );
      setAnalyses((current) => [result, ...current]);
      onError("");
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Analysis failed.");
    } finally {
      setBusyId(null);
    }
  };

  const fuse = async () => {
    if (selectedCaseId === null) return;
    setBusyId(-1);
    try {
      const result = await api<Assessment>(`/api/v1/cases/${selectedCaseId}/fusion`, { method: "POST" });
      setAssessments((current) => [result, ...current]);
      onError("");
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Fusion assessment failed.");
    } finally {
      setBusyId(null);
    }
  };

  const confirmLink = async () => {
    if (selectedEdgeId === null) return;
    try {
      await api(`/api/v1/graph/links/${selectedEdgeId}/confirm`, { method: "POST" });
      onError("");
      setSelectedEdgeId(null);
      await loadGraph();
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Link could not be confirmed.");
    }
  };

  const decide = async (item: QueueItem, decision: "CONFIRM" | "REJECT" | "ESCALATE") => {
    setBusyId(item.assessment_id);
    try {
      await api(`/api/v1/review-queue/${item.assessment_id}/decision`, {
        method: "POST",
        body: JSON.stringify({ decision, notes: notes[item.assessment_id] ?? "" }),
      });
      await loadQueue();
      await onRefresh();
      onError("");
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Review decision could not be recorded.");
    } finally {
      setBusyId(null);
    }
  };

  const downloadReport = async (record: CaseRecord) => {
    try {
      const response = await fetch(`/api/v1/cases/${record.id}/report.pdf`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(typeof body.detail === "string" ? body.detail : `Report failed (${response.status})`);
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `${record.case_number}-report.pdf`;
      link.click();
      URL.revokeObjectURL(url);
      await onRefresh();
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Report generation failed.");
    }
  };

  const latestAssessment = assessments[0];
  const chartData = useMemo(() => ({
    labels: assessments.slice().reverse().map((item) => new Date(item.created_at).toLocaleDateString()),
    datasets: [{
      label: "Review-priority score",
      data: assessments.slice().reverse().map((item) => item.score),
      borderColor: "#82dfa0",
      backgroundColor: "rgba(130,223,160,.12)",
      pointBackgroundColor: "#b5f3c4",
      fill: true,
      tension: 0.35,
    }],
  }), [assessments]);

  useEffect(() => {
    if (!graphHost.current || mode !== "network") return;
    const cy = cytoscape({
      container: graphHost.current,
      elements: [...graph.nodes, ...graph.edges],
      layout: { name: "cose", animate: false, fit: true, padding: 40 },
      style: [
        { selector: "node", style: { "background-color": "#426454", "label": "data(label)", color: "#e4eeee", "font-size": "10px", "text-wrap": "wrap", "text-max-width": "115px", width: "36px", height: "36px", "border-width": "1px", "border-color": "#8bdda5" } },
        { selector: 'node[kind = "case"]', style: { "background-color": "#254333", shape: "round-rectangle", width: "120px", height: "42px", "font-size": "11px", "border-width": "2px" } },
        { selector: 'node[kind = "wallet"]', style: { "background-color": "#594e31", "border-color": "#d9c77b" } },
        { selector: 'node[kind = "url"], node[kind = "invite_link"]', style: { "background-color": "#344c61", "border-color": "#84b6df" } },
        { selector: "edge", style: { width: "2px", "line-color": "#76858a", "target-arrow-color": "#76858a", "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)", color: "#a7b8bb", "font-size": "8px", "text-background-color": "#111b20", "text-background-opacity": 1, "text-background-padding": "2px" } },
        { selector: 'edge[status = "CONFIRMED"]', style: { "line-color": "#8de4a7", "target-arrow-color": "#8de4a7", width: "3px" } },
        { selector: "edge:selected", style: { "line-color": "#f0cf7e", "target-arrow-color": "#f0cf7e", width: "4px" } },
      ],
    });
    cy.on("tap", "edge", (event) => setSelectedEdgeId(event.target.data("link_id") as number));
    return () => {
      cy.stop();
      cy.destroy();
    };
  }, [graph, mode]);

  useEffect(() => {
    if (!selectedCaseId || !token) {
      setImagePreview(null);
      return;
    }
    const latestImageRun = analyses.find((run) => run.signals.visual?.status === "complete");
    const imageEvidence = evidence.find((item) => item.id === latestImageRun?.evidence_id);
    if (!imageEvidence) {
      setImagePreview(null);
      return;
    }
    let objectUrl = "";
    let active = true;
    setImagePreview({ evidenceId: imageEvidence.id, url: "", error: null });
    void fetch(`/api/v1/evidence/${imageEvidence.id}/download`, {
      headers: { Authorization: `Bearer ${token}` },
    }).then((response) => response.ok ? response.blob() : Promise.reject(new Error("Preview could not be loaded")))
      .then((blob) => {
        objectUrl = URL.createObjectURL(blob);
        if (active) setImagePreview({ evidenceId: imageEvidence.id, url: objectUrl, error: null });
        else URL.revokeObjectURL(objectUrl);
      }).catch((cause: unknown) => {
        if (active) setImagePreview({
          evidenceId: imageEvidence.id,
          url: "",
          error: cause instanceof Error ? cause.message : "Preview could not be loaded.",
        });
      });
    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [analyses, evidence, selectedCaseId, token]);

  if (mode === "network") {
    const possibleCount = graph.edges.filter((edge) => edge.data.status === "POSSIBLE").length;
    const confirmedCount = graph.edges.length - possibleCount;
    return <section className="panel tool-panel">
      <div className="section-heading"><div><p className="eyebrow">CASE CORRELATION</p><h2>Entity network</h2><p className="muted">Links reflect repeated entities found only in uploaded files; they are possible until a human confirms them.</p></div><button className="secondary compact" onClick={() => void loadGraph()}>Refresh graph</button></div>
      <div className="graph-stats"><span><strong>{graph.nodes.filter((node) => node.data.kind === "case").length}</strong> cases</span><span><strong>{graph.nodes.filter((node) => node.data.kind !== "case").length}</strong> entities</span><span><strong>{possibleCount}</strong> possible links</span><span><strong>{confirmedCount}</strong> confirmed links</span></div>
      <div className="graph-canvas" ref={graphHost} />
      {selectedEdgeId !== null && graph.edges.find((edge) => edge.data.link_id === selectedEdgeId)?.data.status === "POSSIBLE" && <div className="graph-confirm"><span>Selected link is a candidate, not a finding. Confirm only after reviewing its evidence.</span><button onClick={() => void confirmLink()}>Confirm relationship</button></div>}
      {graph.nodes.length === 0 && <div className="empty graph-empty"><strong>No relationship data yet</strong><p>Analyze benign JSON exports in the Analysis Lab to extract fabricated entities for this local graph.</p></div>}
    </section>;
  }

  if (mode === "review") {
    if (role !== "REVIEWER" && role !== "ADMIN") {
      return <section className="panel tool-panel"><div className="empty"><strong>Reviewer access required</strong><p>This queue is available to reviewer and admin roles only.</p></div></section>;
    }
    return <section className="panel tool-panel">
      <div className="section-heading"><div><p className="eyebrow">HUMAN DECISION REQUIRED</p><h2>Review queue</h2><p className="muted">All signal components are shown. Nothing here triggers reporting or actions automatically.</p></div><span className="counter">{queue.length} awaiting</span></div>
      {queue.length === 0 ? <div className="empty"><strong>Queue is clear</strong><p>Fusion assessments will appear here for a human decision.</p></div> : <div className="review-list">{queue.map((item) => <article className="review-card" key={item.assessment_id}>
        <div className="review-heading"><div><span className="eyebrow">{item.case_number} · ASSESSMENT {item.assessment_id}</span><h3>{item.case_title}</h3><small>{new Date(item.created_at).toLocaleString()} · {item.signal_runs.length} signal runs</small></div><div className={tierClass(item.tier)}>{tierLabel(item.tier)}<strong>{Math.round(item.score * 100)}%</strong></div></div>
        <p className="muted review-explanation">{item.explanation.explanation}</p>
        <div className="signal-grid">{Object.entries(item.explanation.components ?? {}).map(([name, part]) => <div className="signal-chip" key={name}><span>{name.replace(/_/g, " ")}</span><strong>{part.observed}</strong><small>{Math.round(part.contribution * 100)}% contribution</small></div>)}</div>
        <div className="review-run-summary"><strong>Underlying signals</strong>{item.signal_runs.map((run) => <span key={run.id}>{run.signals.evidence.filename}: {run.signals.language?.cue_category_count ?? 0} language categories · {run.signals.visual?.duplicate_candidates?.length ?? 0} image reuse candidates · {run.signals.behavior?.message_count ?? 0} messages</span>)}</div>
        <label className="review-notes">Reviewer notes<textarea value={notes[item.assessment_id] ?? ""} onChange={(event) => setNotes((current) => ({ ...current, [item.assessment_id]: event.target.value }))} maxLength={2000} rows={2} placeholder="Record context and reasoning. Avoid conclusions unsupported by evidence." /></label>
        <div className="review-actions"><button className="confirm-action" disabled={busyId === item.assessment_id} onClick={() => void decide(item, "CONFIRM")}>Confirm cue</button><button className="secondary" disabled={busyId === item.assessment_id} onClick={() => void decide(item, "REJECT")}>Reject cue</button><button className="escalate-action" disabled={busyId === item.assessment_id} onClick={() => void decide(item, "ESCALATE")}>Escalate for human review</button></div>
      </article>)}</div>}
    </section>;
  }

  if (mode === "reports") {
    return <section className="panel tool-panel">
      <div className="section-heading"><div><p className="eyebrow">EVIDENCE SUMMARY</p><h2>Case reports</h2><p className="muted">Generate an auditable PDF with evidence hashes, analysis signals, score explanations, network summary, and any reviewer decisions.</p></div></div>
      {cases.length === 0 ? <div className="empty"><strong>No cases available</strong><p>Create a synthetic case to generate a report.</p></div> : <div className="report-grid">{cases.map((record) => <article className="report-card" key={record.id}><span className="eyebrow">{record.case_number}</span><h3>{record.title}</h3><p className="muted">Includes only evidence metadata and analyst/reviewer notes. Original evidence files are not embedded.</p><button onClick={() => void downloadReport(record)}>Generate &amp; download PDF</button></article>)}</div>}
    </section>;
  }

  return <section className="analysis-layout">
    <aside className="panel analysis-sidebar">
      <div className="section-heading"><div><p className="eyebrow">ANALYSIS SUBJECT</p><h2>Case files</h2></div></div>
      <div className="case-list">{cases.map((record) => <button key={record.id} className={`case-picker${selectedCaseId === record.id ? " selected" : ""}`} onClick={() => onSelectCase(record.id)}><span className="case-meta">{record.case_number}</span><strong>{record.title}</strong></button>)}</div>
      <div className="analysis-guardrail"><strong>Synthetic evidence only</strong><span>Run analysis manually. No automatic findings or external data collection.</span></div>
    </aside>
    <div className="analysis-main">
      {!selectedCase ? <section className="panel empty analysis-empty"><strong>Select a case to explore patterns</strong><p>Analysis is performed only on files explicitly uploaded to the selected case.</p></section> : <>
        <section className="panel">
          <div className="section-heading"><div><p className="eyebrow">{selectedCase.case_number}</p><h2>{selectedCase.title}</h2><p className="muted">Run a transparent signal pass on each benign evidence item, then explicitly request fusion.</p></div>{role !== "REVIEWER" && <button disabled={busyId === -1 || evidence.length === 0} onClick={() => void fuse()}>{busyId === -1 ? "Combining signals…" : "Run fusion"}</button>}</div>
          {evidence.length === 0 ? <div className="empty"><strong>No evidence available</strong><p>Add benign synthetic files in the Evidence Lab first.</p></div> : <div className="analysis-evidence-list">{evidence.map((item) => <div className="analysis-evidence" key={item.id}><div><strong>{item.original_filename}</strong><small>{item.media_type} · {formatBytes(item.size_bytes)} · SHA-256 {item.sha256.slice(0, 14)}…</small></div>{role !== "REVIEWER" && <button className="secondary compact" disabled={busyId === item.id} onClick={() => void analyze(item)}>{busyId === item.id ? "Analyzing…" : "Analyze evidence"}</button>}</div>)}</div>}
        </section>
        {latestAssessment && <section className="panel fusion-panel">
          <div className="fusion-summary"><div><span className="eyebrow">HUMAN REVIEW PRIORITY · NOT A CLASSIFICATION</span><h3 className={tierClass(latestAssessment.tier)}>{tierLabel(latestAssessment.tier)}</h3><p className="muted">{latestAssessment.explanation}</p></div><div className="score-orbit" style={{ "--score": `${latestAssessment.score * 100}%` } as CSSProperties}><strong>{Math.round(latestAssessment.score * 100)}</strong><small>SCORE</small></div></div>
          <div className="signal-grid">{Object.entries(latestAssessment.components ?? {}).map(([name, part]) => <div className="signal-chip" key={name}><span>{name.replace(/_/g, " ")}</span><strong>{part.observed}</strong><small>weight {Math.round(part.weight * 100)}% · contributed {Math.round(part.contribution * 100)}%</small></div>)}</div>
        </section>}
        {assessments.length > 1 && <section className="panel chart-panel"><div className="section-heading"><div><p className="eyebrow">ASSESSMENT HISTORY</p><h2>Review-priority trend</h2></div></div><Line data={chartData} options={{ responsive: true, plugins: { legend: { labels: { color: "#aebbbd" } } }, scales: { x: { ticks: { color: "#899a9e" }, grid: { color: "#2a383e" } }, y: { min: 0, max: 1, ticks: { color: "#899a9e" }, grid: { color: "#2a383e" } } } }} /></section>}
        {analyses.length > 0 && <SignalTimeline analyses={analyses} />}
        {analyses.map((run) => {
          const runPreview = imagePreview?.evidenceId === run.evidence_id ? imagePreview : null;
          return <AnalysisCard
            key={run.id}
            run={run}
            imagePreview={runPreview?.url ?? ""}
            previewLoading={runPreview !== null && !runPreview.url && !runPreview.error}
            previewError={runPreview?.error ?? ""}
          />;
        })}
      </>}
    </div>
  </section>;
}

type TimelineFilter = "all" | "language" | "behavior" | "visual" | "entities";

function SignalTimeline({ analyses }: { analyses: AnalysisRecord[] }) {
  const [filter, setFilter] = useState<TimelineFilter>("all");
  const filters: Array<{ id: TimelineFilter; label: string }> = [
    { id: "all", label: "All runs" },
    { id: "language", label: "Language cues" },
    { id: "behavior", label: "Behavior" },
    { id: "visual", label: "Visual" },
    { id: "entities", label: "Entities" },
  ];
  const orderedRuns = analyses.slice().reverse();
  const filteredRuns = orderedRuns.filter((run) => {
    const signals = run.signals;
    const entityCount = Object.values(signals.language?.entities ?? {}).reduce(
      (total, values) => total + values.length,
      0,
    );
    if (filter === "language") return (signals.language?.cue_category_count ?? 0) > 0;
    if (filter === "behavior") return (signals.behavior?.message_count ?? 0) > 0;
    if (filter === "visual") return signals.visual?.status === "complete";
    if (filter === "entities") return entityCount > 0;
    return true;
  });

  return <section className="panel signal-timeline">
    <div className="section-heading">
      <div><p className="eyebrow">CASE ACTIVITY</p><h2>Signal timeline</h2><p className="muted">Select a run to inspect its source and full analysis. Filters only narrow the displayed runs.</p></div>
      <span className="counter">{filteredRuns.length} / {analyses.length} runs</span>
    </div>
    <div className="timeline-filters" role="group" aria-label="Filter analysis runs by signal">
      {filters.map((item) => <button
        type="button"
        className={`timeline-filter${filter === item.id ? " active" : ""}`}
        aria-pressed={filter === item.id}
        key={item.id}
        onClick={() => setFilter(item.id)}
      >{item.label}</button>)}
    </div>
    {filteredRuns.length === 0 ? <div className="empty timeline-empty"><strong>No runs match this filter</strong><p>Choose another signal type or run analysis on uploaded evidence.</p></div> : <div className="timeline-list">
      {filteredRuns.map((run) => {
        const signals = run.signals;
        const cueCount = signals.language?.cue_category_count ?? 0;
        const messageCount = signals.behavior?.message_count ?? 0;
        const duplicateCount = signals.visual?.duplicate_candidates?.length ?? 0;
        const entityCount = Object.values(signals.language?.entities ?? {}).reduce(
          (total, values) => total + values.length,
          0,
        );
        return <button
          className="timeline-entry"
          key={run.id}
          type="button"
          onClick={() => document.getElementById(`analysis-run-${run.id}`)?.scrollIntoView({ behavior: "smooth", block: "center" })}
        >
          <span className="timeline-marker" aria-hidden="true" />
          <span className="timeline-entry-main">
            <span className="timeline-entry-heading"><strong>{signals.evidence.filename}</strong><small>{new Date(run.created_at).toLocaleString()}</small></span>
            <span className="timeline-entry-signals">
              {cueCount > 0 && <span>{cueCount} language cue groups</span>}
              {messageCount > 0 && <span>{messageCount} messages</span>}
              {duplicateCount > 0 && <span>{duplicateCount} visual reuse candidates</span>}
              {entityCount > 0 && <span>{entityCount} extracted entities</span>}
              {cueCount === 0 && messageCount === 0 && duplicateCount === 0 && entityCount === 0 && <span>No configured cues or repeats observed</span>}
            </span>
          </span>
          <span className="timeline-open">View results</span>
        </button>;
      })}
    </div>}
  </section>;
}

function AnalysisCard({ run, imagePreview, previewLoading, previewError }: { run: AnalysisRecord; imagePreview: string; previewLoading: boolean; previewError: string }) {
  const { signals } = run;
  const cues = signals.language?.language_cue_categories ?? [];
  const entities = signals.language?.entities ?? {};
  const visual: VisualSignals = signals.visual ?? { status: "not_applicable" };
  const behavior: BehaviorSignals = signals.behavior ?? { status: "not_applicable" };
  return <article id={`analysis-run-${run.id}`} className="panel analysis-result">
    <div className="section-heading"><div><p className="eyebrow">ANALYSIS RUN {run.id} · {new Date(run.created_at).toLocaleString()}</p><h2>{signals.evidence.filename}</h2><p className="muted">SHA-256 {signals.evidence.sha256}</p></div><span className="pill status-open">SIGNALS ONLY</span></div>
    <div className="result-grid">
      {visual.status === "complete" && <section className="result-block"><div className="result-title"><span>VISUAL · OBJECT METADATA</span><small>{visual.width} × {visual.height} px · {visual.mode}</small></div><VisionCanvas imagePreview={imagePreview} sha256={signals.evidence.sha256} hash={visual.perceptual_hash ?? "n/a"} duplicateCount={visual.duplicate_candidates?.length ?? 0} loading={previewLoading} previewError={previewError} /><div className="hash-line"><span>Perceptual hash</span><code>{visual.perceptual_hash}</code></div><div className="hash-line"><span>Duplicate candidates</span><strong>{visual.duplicate_candidates?.length ?? 0}</strong></div><p className="muted">{visual.scope}</p>{visual.ocr && <p className="tool-unavailable">{visual.ocr.message}{visual.ocr.status === "complete" && visual.ocr.text ? ` ${visual.ocr.text}` : ""}</p>}</section>}
      {signals.language?.status === "complete" && <section className="result-block"><div className="result-title"><span>LANGUAGE · PATTERN PROMPTS</span><small>{signals.language.token_count} tokens · {signals.language.message_count} messages</small></div>{cues.length ? <div className="cue-list">{cues.map((cue: {category:string;cue_count:number}) => <span key={cue.category}>{cue.category.replace(/_/g, " ")} <strong>{cue.cue_count}</strong></span>)}</div> : <p className="muted">No configured phrase cues observed. This is not proof of absence.</p>}<p className="muted">{signals.language.review_note}</p><div className="entity-list">{Object.entries(entities).flatMap(([kind, values]) => (values as string[]).map((value) => <span key={`${kind}-${value}`}>{kind}: {value}</span>))}</div><div className="keyword-list">{(signals.language.keywords ?? []).map((keyword: {term:string;count:number}) => <span key={keyword.term}>{keyword.term} <b>{keyword.count}</b></span>)}</div></section>}
      {behavior.status === "complete" && <section className="result-block"><div className="result-title"><span>BEHAVIOR · UPLOADED EXPORT</span><small>{behavior.source}</small></div><div className="behavior-stats"><div><strong>{behavior.message_count}</strong><small>messages</small></div><div><strong>{behavior.distinct_senders}</strong><small>senders</small></div><div><strong>{behavior.messages_per_hour ?? "—"}</strong><small>messages/hour</small></div></div>{(behavior.repeated_senders ?? []).map((sender) => <p className="muted" key={sender.sender}>Repeated: {sender.sender} · {sender.message_count} messages</p>)}</section>}
      {signals.voice && <section className="result-block"><div className="result-title"><span>VOICE</span></div><p className="tool-unavailable">{signals.voice.message}</p></section>}
      <section className="result-block"><div className="result-title"><span>LOCAL DUMMY HASH LIST</span></div><p className="muted">{signals.known_hash.match ? "Matched harmless synthetic fixture only." : "No match in local harmless dummy list. This is not a search against an external database."}</p></section>
    </div>
  </article>;
}

function VisionCanvas({ imagePreview, sha256, hash, duplicateCount, loading, previewError }: { imagePreview: string; sha256: string; hash: string; duplicateCount: number; loading: boolean; previewError: string }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [imageDrawFailed, setImageDrawFailed] = useState(false);

  useEffect(() => {
    if (!imagePreview || !canvasRef.current) {
      if (canvasRef.current) {
        const context = canvasRef.current.getContext("2d");
        context?.clearRect(0, 0, canvasRef.current.width, canvasRef.current.height);
      }
      setImageDrawFailed(false);
      return;
    }
    const canvas = canvasRef.current;
    const context = canvas.getContext("2d");
    if (!context) return;
    const image = new Image();
    let active = true;
    setImageDrawFailed(false);
    image.onload = () => {
      if (!active) return;
      const w = 420;
      const h = 240;
      canvas.width = w;
      canvas.height = h;
      context.clearRect(0, 0, w, h);
      context.fillStyle = "#172329";
      context.fillRect(0, 0, w, h);
      const scale = Math.min(w / image.width, h / image.height) * zoom;
      const drawWidth = image.width * scale;
      const drawHeight = image.height * scale;
      const offsetX = (w - drawWidth) / 2 + pan.x;
      const offsetY = (h - drawHeight) / 2 + pan.y;
      context.drawImage(image, offsetX, offsetY, drawWidth, drawHeight);
    };
    image.onerror = () => {
      if (active) setImageDrawFailed(true);
    };
    image.src = imagePreview;
    return () => {
      active = false;
      image.onload = null;
      image.onerror = null;
    };
  }, [imagePreview, pan, zoom]);

  return <div className="vision-canvas-wrap">
    <div className="vision-auth-header">
      <div><span className="eyebrow">LOCAL EVIDENCE VIEW</span><strong>Integrity canvas</strong></div>
      <span className={`vision-auth-status${imagePreview && !imageDrawFailed ? " verified" : ""}`}><i aria-hidden="true" />{imagePreview && !imageDrawFailed ? "SHA-256 verified on retrieval" : loading ? "Loading verified preview" : "Preview unavailable"}</span>
    </div>
    <div className={`vision-stage${imagePreview && !imageDrawFailed ? " verified" : ""}`}>
      <canvas ref={canvasRef} className="vision-canvas" aria-label="Uploaded evidence image preview. No person classification is performed." />
      {imagePreview && !imageDrawFailed && <><span className="vision-grid" aria-hidden="true" /><span className="vision-sweep" aria-hidden="true" /></>}
      <span className="vision-stage-caption">UPLOADED FILE · VISUAL INSPECTION ONLY</span>
      {!imagePreview && <span className="vision-stage-message">{loading ? "Retrieving the hash-checked preview…" : previewError ? "The preview could not be loaded." : "Preview is available for the latest analyzed image."}</span>}
      {imageDrawFailed && <span className="vision-stage-message">The downloaded file could not be rendered as an image.</span>}
    </div>
    <div className="vision-auth-facts">
      <span><small>Recorded SHA-256</small><code>{sha256.slice(0, 18)}…</code></span>
      <span><small>Perceptual hash</small><code>{hash}</code></span>
      <span><small>Reuse candidates</small><strong>{duplicateCount}</strong></span>
    </div>
    {previewError && <p className="vision-error" role="status">{previewError}</p>}
    <div className="vision-toolbar">
      <div className="vision-zoom-controls">
        <button type="button" className="secondary compact" aria-label="Zoom out" disabled={zoom <= 0.8} onClick={() => setZoom((current) => Math.max(0.8, Number((current - 0.15).toFixed(2))))}>-</button>
        <span>{Math.round(zoom * 100)}%</span>
        <button type="button" className="secondary compact" aria-label="Zoom in" disabled={zoom >= 1.8} onClick={() => setZoom((current) => Math.min(1.8, Number((current + 0.15).toFixed(2))))}>+</button>
        <button type="button" className="secondary compact" onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}>Reset view</button>
      </div>
      <label className="vision-pan-control">Pan X<input aria-label="Vision canvas pan horizontal" type="range" min={-30} max={30} value={pan.x} onChange={(event) => setPan((current) => ({ ...current, x: Number(event.target.value) }))} /></label>
      <label className="vision-pan-control">Pan Y<input aria-label="Vision canvas pan vertical" type="range" min={-30} max={30} value={pan.y} onChange={(event) => setPan((current) => ({ ...current, y: Number(event.target.value) }))} /></label>
    </div>
    <p className="vision-disclaimer">A matching SHA-256 confirms the retrieved file matches its recorded upload hash; it does not establish who or what is depicted.</p>
  </div>;
}

function formatBytes(size: number): string {
  return size < 1024 * 1024 ? `${(size / 1024).toFixed(1)} KB` : `${(size / (1024 * 1024)).toFixed(2)} MB`;
}
