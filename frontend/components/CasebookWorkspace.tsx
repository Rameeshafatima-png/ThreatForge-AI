
import { useCallback, useEffect, useMemo, useState } from "react";
import { apiUrl } from "../lib/api";

type Evidence = {
  source?: string;
  type?: string;
  value?: string;
  provenance?: string;
};

type AgentExecution = {
  agent: string;
  status: string;
  summary?: string;
  errors?: string[];
  duration_ms?: number | null;
};

type Hypothesis = {
  pattern: string;
  basis: string;
  confidence: string;
  not_confirmed?: string;
  source?: string;
};

type SecurityEvent = {
  timestamp?: string | null;
  host?: string | null;
  service?: string | null;
  source_ip?: string | null;
  username?: string | null;
  outcome?: string | null;
  raw?: string;
};

type Investigation = {
  id: string;
  prompt: string;
  status: string;
  report_status: string;
  created_at?: string;
  result?: {
    evidence?: Evidence[];
    agent_executions?: AgentExecution[];
    log_analysis?: {
      failed_attempt_count?: number;
      successful_login_count?: number;
      session_event_count?: number;
      anomaly_count?: number;
      affected_usernames?: string[];
      source_ips?: string[];
      target_hosts?: string[];
      events?: SecurityEvent[];
    };
    correlation?: {
      hypothesis_count?: number;
      hypotheses?: Hypothesis[];
    };
    risk_report?: {
      classification?: string;
      severity?: string;
      confidence?: string;
      severity_rationale?: string;
      executive_summary?: string;
      hypothesis_count?: number;
      observed_facts?: string[];
      recommendations?: string[];
      unknowns?: string[];
      uncertainty?: string[];
    };
  };
};

function normalize(value?: string) {
  return (value || "").toLowerCase().replace(/[_-]/g, " ").trim();
}

function StatusPill({ status }: { status: string }) {
  const value = normalize(status) || "unknown";

  return (
    <span className={`status-pill status-pill-${value.replace(/\s+/g, "-")}`}>
      {value}
    </span>
  );
}

function SectionHeader({
  number,
  label,
  title,
  description,
}: {
  number: string;
  label: string;
  title: string;
  description?: string;
}) {
  return (
    <div className="mb-5">
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10px] text-forge-gold">
          {number}
        </span>
        <span className="eyebrow">{label}</span>
      </div>
      <h4 className="mt-2 text-lg font-semibold tracking-tight text-forge-text">
        {title}
      </h4>
      {description && (
        <p className="mt-2 max-w-2xl text-xs leading-5 text-forge-muted">
          {description}
        </p>
      )}
    </div>
  );
}

function MetricCard({
  label,
  value,
  description,
}: {
  label: string;
  value: string | number;
  description: string;
}) {
  return (
    <div className="input-evidence-panel min-w-0">
      <p className="eyebrow">{label}</p>
      <p className="mt-3 break-words text-2xl font-semibold tracking-tight text-forge-text">
        {value}
      </p>
      <p className="mt-2 text-[10px] leading-4 text-forge-muted">
        {description}
      </p>
    </div>
  );
}

function EmptyState({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-lg border border-dashed border-forge-border px-4 py-5">
      <p className="text-xs font-medium text-forge-text">{title}</p>
      <p className="mt-2 text-xs leading-5 text-forge-muted">
        {description}
      </p>
    </div>
  );
}

function InformationList({
  items,
  emptyText,
}: {
  items?: string[];
  emptyText: string;
}) {
  if (!items?.length) {
    return (
      <p className="text-xs leading-5 text-forge-muted">
        {emptyText}
      </p>
    );
  }

  return (
    <ul className="space-y-3">
      {items.map((item, index) => (
        <li
          key={`${index}-${item}`}
          className="flex items-start gap-3 text-xs leading-5 text-forge-muted"
        >
          <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-forge-gold" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

export function CasebookWorkspace({
  selectedId,
}: {
  selectedId: string;
}) {
  const [selected, setSelected] = useState<Investigation | null>(null);
  const [caseLoading, setCaseLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeAgent, setActiveAgent] = useState("");

  const loadCase = useCallback(async () => {
    if (!selectedId) return;

    setCaseLoading(true);
    setError("");

    try {
      const response = await fetch(
        apiUrl(`/investigations/${encodeURIComponent(selectedId)}`)
      );

      if (!response.ok) {
        const data = await response.json().catch(() => null);
        throw new Error(data?.detail || "Workspace could not be loaded.");
      }

      const data: Investigation = await response.json();

      setSelected(data);
      setActiveAgent(
        data.result?.agent_executions?.[0]?.agent || ""
      );

      window.localStorage.setItem(
        "threatforge_active_investigation",
        selectedId
      );
    } catch (err) {
      setSelected(null);
      setError(
        err instanceof Error ? err.message : "Unable to load workspace."
      );
    } finally {
      setCaseLoading(false);
    }
  }, [selectedId]);

  useEffect(() => {
    void loadCase();
  }, [loadCase]);

  const result = selected?.result;
  const agents = result?.agent_executions || [];
  const evidence = result?.evidence || [];
  const report = result?.risk_report;
  const hypotheses = result?.correlation?.hypotheses || [];
  const logAnalysis = result?.log_analysis;
  const events = logAnalysis?.events || [];

  const currentAgent = agents.find(
    (agent) => agent.agent === activeAgent
  );

  const severity = normalize(report?.severity) || "unknown";
  const confidence = normalize(report?.confidence) || "unknown";

  const severityColor =
    severity === "critical" || severity === "high"
      ? "#F08080"
      : severity === "medium"
        ? "#E8BD75"
        : severity === "low"
          ? "#A9D78A"
          : "#D5BB7C";

  const submittedSubject = useMemo(() => {
    const prompt = selected?.prompt || "";
    return prompt.replace(
      /^\s*(IP Intelligence|URL Analysis|File Analysis|Log Intelligence|Incident Response)\s*:\s*/i,
      ""
    ).trim();
  }, [selected?.prompt]);

  const hasEvidence = evidence.length > 0;
  const hasLogs = events.length > 0;
  const hasHypotheses = hypotheses.length > 0;

  const summary =
    report?.executive_summary ||
    (hasEvidence || hasLogs
      ? "The investigation processed the submitted evidence. Review the evidence, correlation findings and assessment limitations below before drawing conclusions."
      : "The investigation completed, but the submitted information did not contain extractable indicators or parsed security events. A reliable threat assessment cannot be established from the available input.");

  const pipeline = agents.map((agent) => ({
    ...agent,
    displayName: agent.agent.replace(/Agent/gi, "").trim(),
  }));

  const recordedUncertainty = [
    ...(report?.uncertainty || []),
    ...(report?.unknowns || []),
  ].filter((item, index, all) => all.indexOf(item) === index);

  const hasLogCounters =
    logAnalysis?.failed_attempt_count !== undefined ||
    logAnalysis?.successful_login_count !== undefined ||
    logAnalysis?.session_event_count !== undefined;

  return (
    <section
      className="content-section"
      style={{ scrollMarginTop: "100px", paddingTop: "36px" }}
    >
      <div className="workspace-section space-y-6">

        {/* WORKSPACE HEADER */}
        <div className="relative overflow-hidden rounded-xl border border-forge-border bg-[#0A0E10] p-5 sm:p-7">
          <div
            className="pointer-events-none absolute -right-20 -top-24 h-64 w-64 rounded-full opacity-10 blur-3xl"
            style={{ background: "#C7FF72" }}
          />

          <div className="relative">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-[#C7FF72] shadow-[0_0_12px_#C7FF72]" />
                <span className="font-mono text-[9px] tracking-[2px] text-[#C7FF72]">
                  THREATFORGE / INTELLIGENCE WORKSPACE
                </span>
              </div>

              {selected && <StatusPill status={selected.status} />}
            </div>

            <h3 className="mt-6 text-2xl font-semibold tracking-tight text-forge-text sm:text-3xl">
              Investigation Command Center
            </h3>

            <p className="mt-2 max-w-2xl text-xs leading-6 text-forge-muted">
              Evidence processing, threat correlation and AI-assisted security assessment.
            </p>

            {selected && (
              <div className="mt-6 flex flex-col gap-4 border-t border-forge-border pt-5 sm:flex-row sm:items-end sm:justify-between">
                <div className="min-w-0">
                  <p className="eyebrow">ACTIVE INVESTIGATION</p>
                  <p className="mt-2 break-words text-sm font-medium text-forge-text">
                    {selected.prompt}
                  </p>
                  <p className="mt-2 break-all font-mono text-[9px] text-forge-muted">
                    CASE ID / {selected.id}
                  </p>
                </div>

                <button
                  type="button"
                  className="button-secondary shrink-0"
                  onClick={loadCase}
                  disabled={caseLoading}
                >
                  {caseLoading ? "Refreshing..." : "↻ Refresh data"}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* LOADING AND ERROR STATES */}
        {caseLoading ? (
          <div className="state-panel">
            <span className="loading-mark" />
            <p className="mt-3 text-sm text-forge-muted">
              Processing investigation workspace...
            </p>
          </div>
        ) : error ? (
          <div className="state-panel state-panel-error">
            <p className="text-sm" role="alert">{error}</p>
            <button
              type="button"
              className="button-secondary mt-4"
              onClick={loadCase}
            >
              Try again
            </button>
          </div>
        ) : !selected ? (
          <EmptyState
            title="No investigation selected"
            description="Select an investigation from your records to view its findings."
          />
        ) : (
          <>
            {/* TOP ASSESSMENT */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="input-evidence-panel">
                <p className="eyebrow">THREAT LEVEL</p>
                <p
                  className="mt-3 text-xl font-semibold uppercase tracking-wide"
                  style={{ color: severityColor }}
                >
                  {severity}
                </p>
                <p className="mt-2 text-[10px] text-forge-muted">
                  Evidence-based assessment
                </p>
              </div>

              <MetricCard
                label="CONFIDENCE"
                value={confidence}
                description="Confidence in the available findings"
              />

              <MetricCard
                label="INDICATORS"
                value={evidence.length}
                description="Extracted from submitted evidence"
              />

              <MetricCard
                label="CORRELATIONS"
                value={hypotheses.length}
                description="Investigative hypotheses returned"
              />
            </div>

            {/* EXECUTIVE INTELLIGENCE */}
            <section className="workspace-section">
              <SectionHeader
                number="01"
                label="INTELLIGENCE BRIEF"
                title="Investigation Overview"
                description="A consolidated view of what the investigation found and what remains unknown."
              />

              <div className="rounded-xl border border-forge-border bg-[#0A0E10] p-5 sm:p-6">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="eyebrow">EXECUTIVE ASSESSMENT</p>
                  <StatusPill status={selected.report_status} />
                </div>

                <h4 className="mt-4 text-base font-semibold leading-7 text-forge-text">
                  {report?.classification || "Assessment not established"}
                </h4>

                <p className="mt-3 text-xs leading-7 text-forge-muted">
                  {summary}
                </p>

                {!submittedSubject && (
                  <div className="mt-5 rounded-lg border border-[#D5BB7C]/25 bg-[#D5BB7C]/5 p-4">
                    <p className="text-xs font-medium text-[#E5C987]">
                      Evidence input is incomplete
                    </p>
                    <p className="mt-2 text-xs leading-5 text-forge-muted">
                      The submitted request does not contain a value after its investigation label. No URL, IP address, file hash or log content could be assessed from that input.
                    </p>
                  </div>
                )}

                <div className="mt-5 border-t border-forge-border pt-5">
                  <p className="eyebrow">ASSESSMENT RATIONALE</p>
                  <p className="mt-3 text-xs leading-6 text-forge-muted">
                    {report?.severity_rationale ||
                      "A separate severity explanation was not returned by the reporting stage. The displayed severity should therefore be interpreted alongside the available evidence and confidence level."}
                  </p>
                </div>
              </div>
            </section>
            

            {/* INVESTIGATION PIPELINE */}
            <section className="workspace-section">
              <SectionHeader
                number="02"
                label="WORKFLOW MONITOR"
                title="Investigation Pipeline"
                description="Execution records returned by the backend. Only recorded agents are displayed."
              />

              {pipeline.length ? (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {pipeline.map((agent, index) => (
                    <button
                      type="button"
                      key={`${agent.agent}-${index}`}
                      onClick={() => setActiveAgent(agent.agent)}
                      aria-pressed={activeAgent === agent.agent}
                      className={`rounded-lg border p-4 text-left transition-all ${
                        activeAgent === agent.agent
                          ? "border-[#C7FF72]/50 bg-[#C7FF72]/[0.045]"
                          : "border-forge-border bg-[#0A0E10] hover:border-[#C7FF72]/30"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[9px] text-forge-muted">
                          STAGE / 0{index + 1}
                        </span>
                        <StatusPill status={agent.status} />
                      </div>

                      <p className="mt-4 text-sm font-medium text-forge-text">
                        {agent.agent}
                      </p>

                      <p className="mt-2 line-clamp-3 text-xs leading-5 text-forge-muted">
                        {agent.summary || "No execution summary was returned."}
                      </p>

                      {typeof agent.duration_ms === "number" && (
                        <p className="mt-4 border-t border-forge-border pt-3 font-mono text-[9px] text-forge-muted">
                          {agent.duration_ms.toLocaleString()} ms execution
                        </p>
                      )}
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No execution records"
                  description="The backend did not return any agent execution details for this investigation."
                />
              )}
            </section>

            {/* SELECTED AGENT */}
            {currentAgent && (
              <section className="workspace-section">
                <div className="rounded-xl border border-[#C7FF72]/20 bg-[#0A0E10] p-5 sm:p-6">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <p className="eyebrow">AGENT INTELLIGENCE / SELECTED FINDING</p>
                    <StatusPill status={currentAgent.status} />
                  </div>

                  <h4 className="mt-3 text-lg font-semibold text-forge-text">
                    {currentAgent.agent}
                  </h4>

                  <p className="mt-4 text-xs leading-7 text-forge-muted">
                    {currentAgent.summary ||
                      "This agent did not return a detailed execution summary."}
                  </p>

                  {currentAgent.errors?.length ? (
                    <div className="mt-5 border-t border-forge-border pt-4">
                      <p className="eyebrow text-forge-amber">
                        EXECUTION NOTICES
                      </p>
                      <div className="mt-3 space-y-2">
                        {currentAgent.errors.map((item, index) => (
                          <p
                            key={index}
                            className="text-xs leading-5 text-forge-amber"
                          >
                            {item}
                          </p>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p className="mt-4 border-t border-forge-border pt-4 text-[10px] text-forge-muted">
                      No execution errors were recorded.
                    </p>
                  )}
                </div>
              </section>
            )}

            {/* EVIDENCE INTELLIGENCE */}
            <section className="workspace-section">
              <SectionHeader
                number="03"
                label="EVIDENCE INTELLIGENCE"
                title="Collected Indicators"
                description="Indicators extracted from the original submitted material."
              />

              {hasEvidence ? (
                <div className="overflow-hidden rounded-xl border border-forge-border bg-[#0A0E10]">
                  <div className="flex items-center justify-between border-b border-forge-border px-4 py-3">
                    <span className="eyebrow">EXTRACTED EVIDENCE</span>
                    <span className="font-mono text-[10px] text-forge-gold">
                      {evidence.length} RECORDS
                    </span>
                  </div>

                  <div className="divide-y divide-forge-border">
                    {evidence.map((item, index) => (
                      <div
                        key={`${item.type}-${item.value}-${index}`}
                        className="grid grid-cols-1 gap-2 px-4 py-4 sm:grid-cols-[110px_1fr]"
                      >
                        <span className="font-mono text-[10px] uppercase text-forge-gold">
                          {item.type || "Indicator"}
                        </span>

                        <div className="min-w-0">
                          <p className="break-all font-mono text-xs text-forge-text">
                            {item.value || "Value unavailable"}
                          </p>
                          <p className="mt-2 break-words text-[10px] text-forge-muted">
                            {item.provenance || item.source || "Source not specified"}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <EmptyState
                  title="No indicators extracted"
                  description="The submitted material did not contain a recognizable IP address, URL, file hash or other supported indicator."
                />
              )}
            </section>

            {/* THREAT CORRELATION */}
            <section className="workspace-section">
              <SectionHeader
                number="04"
                label="THREAT CORRELATION"
                title="Related Activity & Hypotheses"
                description="Potential relationships identified by the correlation stage. A hypothesis is not proof of an attack."
              />

              {hasHypotheses ? (
                <div className="space-y-3">
                  {hypotheses.map((item, index) => (
                    <div
                      key={`${item.pattern}-${index}`}
                      className="rounded-lg border border-forge-border bg-[#0A0E10] p-4 sm:p-5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-[10px] text-forge-gold">
                            H{String(index + 1).padStart(2, "0")}
                          </span>
                          <h5 className="text-sm font-medium text-forge-text">
                            {item.pattern}
                          </h5>
                        </div>
                        <StatusPill status={item.confidence} />
                      </div>

                      <p className="mt-4 text-xs leading-6 text-forge-muted">
                        {item.basis}
                      </p>

                      {item.not_confirmed && (
                        <p className="mt-4 border-t border-forge-border pt-3 text-xs leading-5 text-forge-amber">
                          Not confirmed: {item.not_confirmed}
                        </p>
                      )}

                      {item.source && (
                        <p className="mt-3 font-mono text-[9px] uppercase text-forge-muted">
                          Source / {item.source}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No correlation patterns identified"
                  description="The correlation stage returned no hypotheses. This does not prove that the submitted system or indicator is safe."
                />
              )}
            </section>

            {/* RISK ASSESSMENT */}
            <section className="workspace-section">
              <SectionHeader
                number="05"
                label="RISK & RESPONSE"
                title="Assessment and Recommendations"
                description="What the available findings indicate and what should be reviewed next."
              />

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-forge-border bg-[#0A0E10] p-5">
                  <p className="eyebrow">OBSERVED FACTS</p>
                  <div className="mt-5">
                    <InformationList
                      items={report?.observed_facts}
                      emptyText="No additional observed facts were returned by the reporting stage."
                    />
                  </div>
                </div>

                <div className="rounded-xl border border-[#C7FF72]/20 bg-[#0A0E10] p-5">
                  <p className="eyebrow">RECOMMENDED NEXT STEPS</p>
                  <div className="mt-5">
                    <InformationList
                      items={report?.recommendations}
                      emptyText="No recommendations were returned."
                    />
                  </div>
                </div>
              </div>
            </section>

            {/* SECURITY EVENTS */}
            <section className="workspace-section">
              <SectionHeader
                number="06"
                label="SECURITY TELEMETRY"
                title="Log Intelligence"
                description="Parsed authentication activity and security events."
              />

              {hasLogCounters && (
                <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <MetricCard
                    label="FAILED ATTEMPTS"
                    value={logAnalysis?.failed_attempt_count ?? "—"}
                    description="Recorded failed authentication events"
                  />
                  <MetricCard
                    label="SUCCESSFUL LOGINS"
                    value={logAnalysis?.successful_login_count ?? "—"}
                    description="Recorded successful authentication events"
                  />
                  <MetricCard
                    label="SESSION EVENTS"
                    value={logAnalysis?.session_event_count ?? "—"}
                    description="Recorded session-related events"
                  />
                </div>
              )}

              {hasLogs ? (
                <details className="group rounded-xl border border-forge-border bg-[#0A0E10]">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-3 p-4">
                    <div>
                      <p className="text-xs font-medium text-forge-text">
                        Parsed security events
                      </p>
                      <p className="mt-1 text-[10px] text-forge-muted">
                        {events.length} event records available
                      </p>
                    </div>
                    <span className="text-sm text-forge-gold transition-transform group-open:rotate-180">
                      ↓
                    </span>
                  </summary>

                  <div className="divide-y divide-forge-border border-t border-forge-border">
                    {events.map((event, index) => (
                      <div key={index} className="p-4">
                        <p className="break-words font-mono text-[10px] leading-5 text-forge-text">
                          {[
                            event.timestamp,
                            event.host,
                            event.service,
                            event.source_ip,
                            event.username,
                            event.outcome,
                          ].filter(Boolean).join(" · ") || "Event details unavailable"}
                        </p>
                        {event.raw && (
                          <p className="mt-2 break-words text-xs leading-5 text-forge-muted">
                            {event.raw}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </details>
              ) : (
                <EmptyState
                  title="No parsed security events"
                  description="No security log events were extracted from the submitted material. Authentication and session activity cannot be assessed without log data."
                />
              )}
            </section>

            {/* LIMITATIONS */}
            <section className="workspace-section">
              <details className="group rounded-xl border border-forge-border bg-[#0A0E10]">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-3 p-5">
                  <div>
                    <p className="eyebrow">ASSESSMENT TRANSPARENCY</p>
                    <h4 className="mt-2 text-sm font-semibold text-forge-text">
                      Limitations & Unverified Information
                    </h4>
                    <p className="mt-2 text-xs text-forge-muted">
                      Review missing information and assessment boundaries.
                    </p>
                  </div>
                  <span className="text-sm text-forge-gold transition-transform group-open:rotate-180">
                    ↓
                  </span>
                </summary>

                <div className="grid grid-cols-1 gap-5 border-t border-forge-border p-5 md:grid-cols-2">
                  <div>
                    <p className="eyebrow">RECORDED UNCERTAINTY</p>
                    <div className="mt-4">
                      <InformationList
                        items={report?.uncertainty}
                        emptyText="No uncertainty entries were returned."
                      />
                    </div>
                  </div>

                  <div>
                    <p className="eyebrow">UNVERIFIED INFORMATION</p>
                    <div className="mt-4">
                      <InformationList
                        items={report?.unknowns}
                        emptyText="No additional unknowns were returned."
                      />
                    </div>
                  </div>

                  {recordedUncertainty.length > 0 && (
                    <p className="text-[10px] leading-5 text-forge-muted md:col-span-2">
                      These limitations describe gaps in the available data. They should be considered before making security decisions.
                    </p>
                  )}
                </div>
              </details>

              <div className="mt-4 rounded-lg border border-[#D5BB7C]/20 bg-[#D5BB7C]/[0.035] p-4">
                <p className="text-xs font-medium text-[#DCC17F]">
                  Assessment boundary
                </p>
                <p className="mt-2 text-xs leading-6 text-forge-muted">
                  Findings are limited to submitted evidence, parsed events and available intelligence results. An absence of detected threat patterns does not establish that a system is free from threats.
                </p>
              </div>
            </section>

            {/* FOOTER */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-forge-border pt-5">
              <div>
                <p className="eyebrow">THREATFORGE INTELLIGENCE ENGINE</p>
                <p className="mt-2 text-[10px] text-forge-muted">
                  Evidence-led assessment · Uncertainty-aware reporting
                </p>
              </div>

              <button
                type="button"
                className="button-secondary"
                onClick={loadCase}
                disabled={caseLoading}
              >
                ↻ Reload investigation
              </button>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
