import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/router";
import { AppLayout } from "../components/AppLayout";
import { apiUrl } from "../lib/api";

const examples = [
  { kind: "IP ADDRESS", placeholder: "IPv4 or IPv6 address", icon: "IP" },
  { kind: "URL / DOMAIN", placeholder: "Domain or full URL", icon: "URL" },
  { kind: "FILE HASH", placeholder: "MD5, SHA-1 or SHA-256", icon: "HASH" },
  { kind: "SECURITY LOG", placeholder: "Paste event records", icon: "LOG" },
  { kind: "INCIDENT", placeholder: "Describe what happened", icon: "CASE" },
];

const agents = [
  { code: "01", name: "Triage agent", detail: "Classifies evidence and sets investigation scope", mark: "TR", tone: "mint" },
  { code: "02", name: "Threat intelligence", detail: "Enriches indicators with external reputation", mark: "TI", tone: "blue" },
  { code: "03", name: "Log analysis", detail: "Finds patterns across security event records", mark: "LA", tone: "violet" },
  { code: "04", name: "Detection engine", detail: "Correlates signals and identifies threats", mark: "DE", tone: "amber" },
  { code: "05", name: "Risk & reporting", detail: "Prioritizes impact and prepares findings", mark: "RR", tone: "rose" },
];

type RecentRecord = { id: string; prompt: string; status: string; report_status: string };

export default function CommandCenter() {
  const router = useRouter();
  const [prompt, setPrompt] = useState("");
  const [backendStatus, setBackendStatus] = useState<"checking" | "ready" | "offline">("checking");
  const [submissionMessage, setSubmissionMessage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [recent, setRecent] = useState<RecentRecord[]>([]);
  const [recentLoading, setRecentLoading] = useState(true);
  const [recentError, setRecentError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    fetch(apiUrl("/health"), { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("Backend health check failed");
        return response.json();
      })
      .then(() => setBackendStatus("ready"))
      .catch((error) => {
        if (error.name !== "AbortError") setBackendStatus("offline");
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetch(apiUrl("/investigations"), { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("Recent investigations are unavailable");
        return response.json();
      })
      .then((records) => setRecent(records))
      .catch((error) => {
        if (error.name !== "AbortError") setRecentError("Could not load recent investigations.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setRecentLoading(false);
      });
    return () => controller.abort();
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!prompt.trim()) return;
    setSubmitting(true);
    setSubmissionMessage("");
    try {
      const response = await fetch(apiUrl("/investigations"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt }),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.detail || "Investigation could not be started");
      }
      const record = await response.json();
      window.localStorage.setItem("threatforge_active_investigation", record.id);
      await router.push(`/workspace?id=${encodeURIComponent(record.id)}`);
    } catch (reason) {
      setSubmissionMessage(
        reason instanceof Error
          ? reason.message
          : "The investigation could not be started. Confirm that the ThreatForge API is online.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  const statusLabel = backendStatus === "ready" ? "All systems operational" : backendStatus === "offline" ? "Backend offline" : "Connecting to backend";
  const statusClass = backendStatus === "ready" ? "status-online" : backendStatus === "offline" ? "status-offline" : "status-pending";

  return (
    <AppLayout>
      <div className="tf-dashboard">
        <header className="tf-topbar">
          <div className="tf-breadcrumb">
            <span className="tf-overline">THREAT OPERATIONS</span>
            <strong>Command Center</strong>
          </div>
          <div className={`tf-system-status ${statusClass}`} role="status">
            <span className="tf-status-dot" />
            {statusLabel}
          </div>
        </header>

        <main className="tf-main">
          <section className="tf-hero">
            <div className="tf-hero-copy">
              <div className="tf-eyebrow"><span className="tf-eyebrow-line" /> AUTONOMOUS SECURITY INTELLIGENCE</div>
              <h1>Stay ahead of<br /><span>the unknown.</span></h1>
              <p className="tf-hero-description">
                One command center for threat intelligence, security signals and AI-powered investigations.
              </p>
              <div className="tf-hero-actions">
                <a href="#investigate" className="tf-primary-link">Start an investigation <span>↗</span></a>
                <a href="#agents" className="tf-secondary-link">Explore AI agents <span>↓</span></a>
              </div>
              <div className="tf-hero-footnote"><span className="tf-live-pulse" /> MULTI-AGENT ANALYSIS · LANGGRAPH WORKFLOW</div>
            </div>
            <div className="tf-globe-panel" aria-label="Abstract global threat activity visualization">
              <div className="tf-globe-topline"><span>GLOBAL THREAT SURFACE</span><span>LIVE MONITOR</span></div>
              <div className="tf-orbit orbit-one" />
              <div className="tf-orbit orbit-two" />
              <div className="tf-globe">
                <div className="tf-globe-grid" />
                <div className="tf-globe-land land-one" />
                <div className="tf-globe-land land-two" />
                <div className="tf-globe-land land-three" />
                <i className="tf-map-point point-one" /><i className="tf-map-point point-two" /><i className="tf-map-point point-three" /><i className="tf-map-point point-four" />
                <span className="tf-map-link link-one" /><span className="tf-map-link link-two" /><span className="tf-map-link link-three" />
              </div>
              <div className="tf-globe-legend"><span><i className="legend-green" /> MONITORED SIGNALS</span><span><i className="legend-white" /> INTELLIGENCE NODES</span></div>
              <div className="tf-globe-coordinates">24.8607° N&nbsp;&nbsp; 67.0011° E</div>
            </div>
          </section>

          <section className="tf-metric-grid" aria-label="Platform overview">
            <article className="tf-metric-card">
              <span className="tf-metric-label">AI INVESTIGATION ENGINE</span>
              <strong>05 <small>AGENTS</small></strong>
              <span className="tf-metric-note">Coordinated analysis pipeline</span>
            </article>
            <article className="tf-metric-card">
              <span className="tf-metric-label">CASEBOOK</span>
              <strong>{String(recent.length).padStart(2, "0")} <small>CASES</small></strong>
              <span className="tf-metric-note">Saved investigation records</span>
            </article>
            <article className="tf-metric-card">
              <span className="tf-metric-label">SYSTEM STATUS</span>
              <strong className={`tf-metric-state ${backendStatus === "ready" ? "is-ready" : ""}`}>{backendStatus === "ready" ? "READY" : backendStatus === "offline" ? "OFFLINE" : "CHECKING"}</strong>
              <span className="tf-metric-note">ThreatForge API connection</span>
            </article>
            <article className="tf-metric-card tf-metric-highlight">
              <span className="tf-metric-label">INTELLIGENCE MODE</span>
              <strong>AI <small>POWERED</small></strong>
              <span className="tf-metric-note">LangGraph orchestration</span>
            </article>
          </section>

          <section className="tf-section-heading" id="investigate">
            <div><span className="tf-overline">01 / EVIDENCE INTAKE</span><h2>Launch an investigation</h2></div>
            <span className="tf-section-aside">IP · URL · HASH · LOGS · INCIDENTS</span>
          </section>

          <section className="tf-intake-layout">
            <form onSubmit={submit} className="tf-intake-card">
              <div className="tf-intake-card-head">
                <div><span className="tf-card-kicker">NEW CASE</span><h3>What should we investigate?</h3></div>
                <span className="tf-intake-symbol">＋</span>
              </div>
              <textarea
                value={prompt}
                onChange={(event) => setPrompt(event.target.value)}
                placeholder="Paste an indicator, security log, or describe the incident..."
                className="tf-evidence-input"
              />
              <div className="tf-intake-footer">
                <span><i className="tf-live-pulse" /> Evidence is processed by the investigation workflow</span>
                <button type="submit" disabled={!prompt.trim() || submitting} className="tf-submit-button">
                  {submitting ? "Starting agents..." : "Run investigation"} <span>↗</span>
                </button>
              </div>
              {submissionMessage && <p className="tf-form-message" role="status">{submissionMessage}</p>}
            </form>
            <aside className="tf-intake-aside">
              <span className="tf-card-kicker">QUICK INPUT</span>
              <p>Choose an evidence type to prefill the investigation field.</p>
              <div className="tf-quick-inputs">
                {examples.map((example) => (
                  <button key={example.kind} type="button" onClick={() => setPrompt(`${example.placeholder}: `)} className="tf-quick-input">
                    <span className="tf-quick-icon">{example.icon}</span><span><strong>{example.kind}</strong><small>{example.placeholder}</small></span><b>↗</b>
                  </button>
                ))}
              </div>
            </aside>
          </section>

          <section className="tf-agents-section" id="agents">
            <div className="tf-section-heading">
              <div><span className="tf-overline">02 / ORCHESTRATION</span><h2>Five agents. One investigation.</h2></div>
              <span className="tf-section-aside">LANGGRAPH-POWERED WORKFLOW</span>
            </div>
            <div className="tf-agent-grid">
              {agents.map((agent) => (
                <article className="tf-agent-card" key={agent.code}>
                  <div className={`tf-agent-mark ${agent.tone}`}>{agent.mark}</div>
                  <span className="tf-agent-number">AGENT {agent.code}</span>
                  <h3>{agent.name}</h3>
                  <p>{agent.detail}</p>
                  <div className="tf-agent-bottom"><span className="tf-agent-indicator" /> READY FOR TASK</div>
                </article>
              ))}
            </div>
          </section>

          <section className="tf-recent-section">
            <div className="tf-section-heading">
              <div><span className="tf-overline">03 / CASEBOOK</span><h2>Recent investigations</h2></div>
              <a href="/history" className="tf-view-all">View casebook <span>↗</span></a>
            </div>
            <div className="tf-recent-card">
              {recentLoading ? (
                <div className="tf-empty-state">Loading investigation records...</div>
              ) : recentError ? (
                <div className="tf-empty-state tf-error-state">{recentError}</div>
              ) : recent.length === 0 ? (
                <div className="tf-empty-state"><span className="tf-empty-icon">⌁</span><div><strong>No investigations yet</strong><p>Your completed and active cases will appear here. Start with an IP, URL, file hash or security event.</p></div><span className="tf-empty-status">AWAITING FIRST CASE</span></div>
              ) : (
                <div className="tf-record-list">
                  {recent.slice(0, 4).map((record) => (
                    <button key={record.id} type="button" className="tf-record-row" onClick={() => {
                      window.localStorage.setItem("threatforge_active_investigation", record.id);
                      router.push(`/workspace?id=${encodeURIComponent(record.id)}`);
                    }}>
                      <span className="tf-record-icon">↗</span>
                      <span className="tf-record-prompt">{record.prompt}</span>
                      <span className="tf-record-status">{record.status}</span>
                      <span className="tf-record-arrow">→</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </section>

          <footer className="tf-footer"><span>THREATFORGE AI</span><span>SECURITY INTELLIGENCE, ORCHESTRATED.</span><span>LOCAL ANALYST WORKSPACE</span></footer>
        </main>
      </div>
    </AppLayout>
  );
}
