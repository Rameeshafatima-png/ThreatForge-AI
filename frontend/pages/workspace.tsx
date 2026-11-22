import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import { AppLayout } from "../components/AppLayout";
import { apiUrl } from "../lib/api";

type AgentStatus = "pending" | "running" | "completed" | "failed" | "skipped";

type AgentExecution = {
  agent: string;
  status: AgentStatus | "error";
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  summary: string;
  output: Record<string, unknown>;
  errors: string[];
};

type Evidence = {
  source: string;
  type: string;
  value: string;
  provenance: string;
};

type Investigation = {
  id: string;
  prompt: string;
  status: string;
  report_status: string;
  created_at: string;
  result: {
    evidence: Evidence[];
    agent_executions: AgentExecution[];
    log_analysis: {
      failed_attempt_count?: number;
      successful_login_count?: number;
      session_event_count?: number;
      network_summary?: {
        record_count?: number;
        patterns?: string[];
      };
      events?: Array<{
        timestamp: string | null;
        host: string | null;
        service: string | null;
        source_ip: string | null;
        username: string | null;
        outcome: string | null;
        raw: string;
      }>;
    };
    correlation: {
      hypothesis_count?: number;
      hypotheses?: Array<{ pattern: string; basis: string; confidence: string }>;
    };
    risk_report: {
      classification?: string;
      severity?: string;
      confidence?: string;
      observed_facts?: string[];
      hypotheses?: Array<{
        pattern: string;
        basis: string;
        confidence: string;
        not_confirmed?: string;
      }>;
    };
  };
};

type AgentStep = {
  name: string;
  label: string;
  code: string;
  purpose: string;
};

const agentSteps: AgentStep[] = [
  {
    name: "Triage Agent",
    label: "Triage",
    code: "01",
    purpose: "Normalize the submitted evidence and plan the investigation.",
  },
  {
    name: "Threat Intelligence Agent",
    label: "Threat intelligence",
    code: "02",
    purpose: "Check extracted indicators against configured reputation providers.",
  },
  {
    name: "Log Analysis Agent",
    label: "Log analysis",
    code: "03",
    purpose: "Parse supplied security events or analyze submitted network-flow features.",
  },
  {
    name: "Threat Detection & Correlation Agent",
    label: "Detection & correlation",
    code: "04",
    purpose: "Correlate available findings into evidence-supported hypotheses.",
  },
  {
    name: "Risk Assessment & Reporting Agent",
    label: "Risk & report",
    code: "05",
    purpose: "Summarize supported facts, uncertainty and recommendations.",
  },
];

function agentStatus(execution: AgentExecution | undefined): AgentStatus {
  if (!execution) return "pending";
  return execution.status === "error" ? "failed" : execution.status;
}

function StatusPill({ status }: { status: string }) {
  return <span className={`status-pill status-pill-${status}`}>{status}</span>;
}

export default function InvestigationWorkspace() {
  const router = useRouter();
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [selectedAgent, setSelectedAgent] = useState(agentSteps[0].name);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!router.isReady) return;

    const queryId = typeof router.query.id === "string" ? router.query.id : null;
    const activeId = queryId || window.localStorage.getItem("threatforge_active_investigation");
    if (!activeId) {
      setInvestigation(null);
      setError("");
      setLoading(false);
      return;
    }

    if (queryId) {
      window.localStorage.setItem("threatforge_active_investigation", queryId);
    }
    const controller = new AbortController();
    setInvestigation(null);
    setError("");
    setLoading(true);

    fetch(apiUrl(`/investigations/${encodeURIComponent(activeId)}`), {
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          const payload = await response.json().catch(() => null);
          throw new Error(payload?.detail || "Investigation could not be loaded");
        }
        return response.json();
      })
      .then((record: Investigation) => setInvestigation(record))
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setError(reason instanceof Error ? reason.message : "Investigation could not be loaded");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
  }, [router.isReady, router.query.id]);

  const executions = investigation?.result?.agent_executions || [];
  const executionsByName = useMemo(
    () => new Map(executions.map((execution) => [execution.agent, execution])),
    [executions],
  );
  const activeExecution = executionsByName.get(selectedAgent);
  const report = investigation?.result?.risk_report;
  const reportReady =
    investigation?.report_status === "generated" &&
    Boolean(report && Object.keys(report).length);
  const renderAgentCard = (step: AgentStep) => {
    const execution = executionsByName.get(step.name);
    const status = agentStatus(execution);
    return (
      <button
        type="button"
        key={step.name}
        onClick={() => setSelectedAgent(step.name)}
        aria-pressed={selectedAgent === step.name}
        className={`agent-card ${selectedAgent === step.name ? "agent-card-active" : ""}`}
      >
        <span className="flex items-center justify-between gap-2">
          <span className="agent-step-code">{step.code}</span>
          <StatusPill status={status} />
        </span>
        <span className="mt-4 block text-sm font-medium leading-5">{step.label}</span>
        <span className="mt-2 block text-xs leading-5 text-forge-muted">
          {execution?.summary || step.purpose}
        </span>
        {execution?.duration_ms != null && (
          <span className="mt-4 block font-mono text-[10px] text-forge-muted">
            {execution.duration_ms} ms
          </span>
        )}
      </button>
    );
  };

  return (
    <AppLayout>
      <header className="page-header">
        <div className="min-w-0">
          <p className="eyebrow">Investigation workspace</p>
          <h1 className="mt-1 truncate text-sm font-medium">
            {investigation?.prompt || "Active investigation"}
          </h1>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {investigation && <StatusPill status={investigation.status} />}
          <Link href="/" className="button-secondary">
            New investigation
          </Link>
        </div>
      </header>

      <main className="page-content page-enter">
        {loading && (
          <div className="state-panel" role="status">
            <span className="loading-mark" aria-hidden="true" />
            <div>
              <p className="text-sm font-medium">Loading investigation</p>
              <p className="mt-1 text-xs text-forge-muted">Retrieving execution results from ThreatForge.</p>
            </div>
          </div>
        )}

        {!loading && error && (
          <div className="state-panel state-panel-error" role="alert">
            <div>
              <p className="text-sm font-medium">Investigation unavailable</p>
              <p className="mt-1 text-xs leading-5 text-forge-muted">{error}</p>
              <Link href="/" className="button-primary mt-5 inline-flex">
                Start an investigation
              </Link>
            </div>
          </div>
        )}

        {!loading && !error && !investigation && (
          <div className="state-panel">
            <div>
              <p className="eyebrow">No active case</p>
              <h2 className="mt-2 text-xl font-medium tracking-tight">Start with the evidence.</h2>
              <p className="mt-2 max-w-md text-sm leading-6 text-forge-muted">
                Submit an indicator, security log or incident description to open a live investigation workspace.
              </p>
              <div className="mt-5 flex flex-wrap gap-2">
                <Link href="/" className="button-primary">Start an investigation</Link>
                <Link href="/history" className="button-secondary">Open casebook</Link>
              </div>
            </div>
          </div>
        )}

        {!loading && !error && investigation && (
          <>
            <section className="workspace-intro">
              <div className="min-w-0">
                <p className="eyebrow">Active investigation</p>
                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="font-mono text-[10px] text-forge-muted">ID {investigation.id}</span>
                  <span className="text-[10px] text-forge-muted">
                    {new Date(investigation.created_at).toLocaleString()}
                  </span>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Link href="/history" className="button-secondary">Casebook</Link>
                {reportReady ? (
                  <Link
                    href={`/report?id=${encodeURIComponent(investigation.id)}`}
                    className="button-primary"
                  >
                    Open completed report
                  </Link>
                ) : (
                  <button type="button" className="button-secondary" disabled>
                    Report not ready
                  </button>
                )}
              </div>
            </section>

            <section className="workspace-section" aria-labelledby="input-heading">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">01 / Evidence intake</p>
                  <h2 id="input-heading" className="section-title">Investigation input</h2>
                </div>
                <span className="font-mono text-[10px] text-forge-muted">
                  {investigation.result.evidence.length} extracted indicator(s)
                </span>
              </div>
              <div className="input-evidence-panel">
                <p className="whitespace-pre-wrap break-words text-sm leading-6 text-forge-text">
                  {investigation.prompt}
                </p>
              </div>
            </section>

            <section className="workspace-section" aria-labelledby="workflow-heading">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">02 / Execution</p>
                  <h2 id="workflow-heading" className="section-title">Five-agent workflow</h2>
                </div>
                <p className="text-xs text-forge-muted">
                  Intelligence and log analysis branch after triage.
                </p>
              </div>

              <div className="workflow-grid">
                {renderAgentCard(agentSteps[0])}
                <span className="workflow-arrow" aria-hidden="true">→</span>
                <div className="workflow-branch">
                  <p className="branch-label">Parallel analysis</p>
                  {renderAgentCard(agentSteps[1])}
                  {renderAgentCard(agentSteps[2])}
                </div>
                <span className="workflow-arrow" aria-hidden="true">→</span>
                {renderAgentCard(agentSteps[3])}
                <span className="workflow-arrow" aria-hidden="true">→</span>
                {renderAgentCard(agentSteps[4])}
              </div>
            </section>

            <div className="workspace-results-grid">
              <section className="workspace-section" aria-labelledby="agent-output-heading">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">03 / Agent output</p>
                    <h2 id="agent-output-heading" className="section-title">
                      {agentSteps.find((step) => step.name === selectedAgent)?.label}
                    </h2>
                  </div>
                  {activeExecution && <StatusPill status={agentStatus(activeExecution)} />}
                </div>
                {activeExecution ? (
                  <div className="agent-output-panel">
                    <p className="text-sm leading-6 text-forge-text">{activeExecution.summary}</p>
                    {activeExecution.errors.length > 0 && (
                      <div className="mt-4 border-l border-forge-red/60 pl-3">
                        <p className="eyebrow text-forge-red">Execution errors</p>
                        {activeExecution.errors.map((item) => (
                          <p key={item} className="mt-1 text-xs leading-5 text-forge-muted">{item}</p>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="agent-output-panel">
                    <p className="text-sm text-forge-text">No execution record for this agent.</p>
                    <p className="mt-1 text-xs leading-5 text-forge-muted">
                      The backend has not reported an execution result for this stage.
                    </p>
                  </div>
                )}
              </section>

              <section className="workspace-section" aria-labelledby="findings-heading">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">04 / Findings</p>
                    <h2 id="findings-heading" className="section-title">Evidence & correlation</h2>
                  </div>
                </div>

                {investigation.result.evidence.length > 0 ? (
                  <div className="evidence-list">
                    {investigation.result.evidence.map((item, index) => (
                      <div key={`${item.type}-${item.value}-${index}`} className="evidence-row">
                        <span className="font-mono text-[9px] uppercase text-forge-gold">{item.type}</span>
                        <div className="min-w-0">
                          <p className="break-all font-mono text-xs text-forge-text">{item.value}</p>
                          <p className="mt-1 text-[10px] leading-4 text-forge-muted">{item.provenance}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="empty-note">No indicators were extracted from the submitted input.</p>
                )}

                {investigation.result.risk_report.observed_facts?.length ? (
                  <div className="mt-5 space-y-2 border-t border-forge-border pt-4">
                    {investigation.result.risk_report.observed_facts.map((fact) => (
                      <p key={fact} className="text-xs leading-5 text-forge-muted">{fact}</p>
                    ))}
                  </div>
                ) : null}

                {investigation.result.correlation.hypotheses?.length ? (
                  <div className="mt-5 space-y-3 border-t border-forge-border pt-4">
                    {investigation.result.correlation.hypotheses.map((hypothesis) => (
                      <div key={hypothesis.pattern}>
                        <p className="text-xs font-medium text-forge-text">{hypothesis.pattern}</p>
                        <p className="mt-1 text-[11px] leading-5 text-forge-muted">{hypothesis.basis}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-4 text-[11px] leading-5 text-forge-muted">
                    No supported correlation hypothesis was returned.
                  </p>
                )}
              </section>
            </div>

            <section className="workspace-footer">
              <div>
                <p className="text-sm font-medium">Continue the investigation</p>
                <p className="mt-1 text-xs text-forge-muted">
                  Start another case or review the completed findings when they are ready.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Link href="/" className="button-secondary">Start another investigation</Link>
                {reportReady && (
                  <Link
                    href={`/report?id=${encodeURIComponent(investigation.id)}`}
                    className="button-primary"
                  >
                    Review report
                  </Link>
                )}
              </div>
            </section>
          </>
        )}
      </main>
    </AppLayout>
  );
}
