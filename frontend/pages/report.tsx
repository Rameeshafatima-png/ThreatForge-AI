import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import { AppLayout } from "../components/AppLayout";
import { apiUrl } from "../lib/api";

type Investigation = {
  id: string;
  prompt: string;
  status: string;
  report_status: string;
  created_at: string;
  result: {
    evidence: Array<{ source: string; type: string; value: string; provenance: string }>;
    agent_executions: Array<{
      agent: string;
      status: string;
      duration_ms: number | null;
      summary: string;
      errors: string[];
    }>;
    triage: Record<string, unknown>;
    log_analysis: {
      network_summary?: {
        record_count?: number;
        patterns?: string[];
      };
    };
    risk_report: {
      classification: string;
      severity: string;
      confidence: string;
      hypothesis_count: number;
      failed_attempt_count: number;
      successful_login_count: number;
      session_event_count: number;
      affected_usernames: string[];
      source_ips: string[];
      target_hosts: string[];
      observed_facts: string[];
      hypotheses: Array<{ pattern: string; basis: string; confidence: string; not_confirmed?: string }>;
      unknowns: string[];
      events: Array<{
        timestamp: string | null;
        host: string | null;
        service: string | null;
        source_ip: string | null;
        username: string | null;
        outcome: string | null;
        raw: string;
      }>;
      uncertainty: string[];
      recommendations: string[];
    };
  };
};

export default function InvestigationReport() {
  const router = useRouter();
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const id =
      typeof router.query.id === "string"
        ? router.query.id
        : window.localStorage.getItem("threatforge_active_investigation");
    if (!id) {
      setLoading(false);
      setError("No investigation selected");
      return;
    }
    fetch(apiUrl(`/investigations/${encodeURIComponent(id)}`))
      .then((response) => {
        if (!response.ok) throw new Error("Investigation report not found");
        return response.json();
      })
      .then((record) => setInvestigation(record))
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Could not load report"))
      .finally(() => setLoading(false));
  }, [router.query.id]);

  const report =
    investigation?.report_status === "generated"
      ? investigation.result?.risk_report
      : undefined;
  const networkSummary = investigation?.result?.log_analysis?.network_summary;
  const networkRecordCount = networkSummary?.record_count || 0;
  const activityMetrics = networkRecordCount
    ? [
        ["Network flows analyzed", String(networkRecordCount)],
        ["Flow patterns identified", String(networkSummary?.patterns?.length || 0)],
        ["Indicators extracted", String(investigation?.result?.evidence?.length || 0)],
      ]
    : report?.failed_attempt_count || report?.successful_login_count || report?.session_event_count
      ? [
          ["Failed SSH attempts", String(report.failed_attempt_count ?? 0)],
          ["Successful logins", String(report.successful_login_count ?? 0)],
          ["Session events", String(report.session_event_count ?? 0)],
          ["Usernames", (report.affected_usernames || []).join(", ") || "None extracted"],
          ["Target hosts", (report.target_hosts || []).join(", ") || "None extracted"],
        ]
      : [
          ["Indicators extracted", String(investigation?.result?.evidence?.length || 0)],
          ["Hypotheses", String(report?.hypothesis_count || 0)],
        ];

  return (
    <AppLayout>
      <header className="page-header">
        <div>
          <p className="eyebrow">Investigation report</p>
          <h1 className="mt-0.5 text-[13px] font-medium">
            {investigation ? "Generated findings" : "Report"}
          </h1>
        </div>
        <Link
          href={investigation ? `/workspace?id=${encodeURIComponent(investigation.id)}` : "/workspace"}
          className="h-8 rounded-md border border-forge-border px-3 py-[7px] text-[11px] text-forge-muted transition hover:border-[#76684b] hover:text-forge-text"
        >
          Open workflow
        </Link>
      </header>

      <main className="page-content page-enter">
        {loading && (
          <div className="flex min-h-[360px] items-center">
            <p className="font-mono text-[11px] text-forge-muted">Loading report payload...</p>
          </div>
        )}
        {!loading && error && (
          <div className="border-b border-forge-border py-10">
            <p className="text-sm text-forge-red">{error}</p>
            <p className="mt-2 text-xs text-forge-muted">Run an investigation to generate report evidence.</p>
          </div>
        )}
        {!loading && investigation && report && (
          <>
            <div className="border-b border-forge-border pb-6">
              <p className="text-[9px] uppercase tracking-[0.18em] text-forge-gold">Completed assessment</p>
              <h1 className="mt-3 max-w-[760px] text-[32px] font-medium leading-[1.05] tracking-[-0.035em]">
                {report.classification}
              </h1>
              <p className="mt-3 max-w-[760px] text-xs leading-5 text-forge-muted">
                {investigation.prompt}
              </p>
            </div>

            <div className="grid border-b border-forge-border md:grid-cols-3">
              {[
                ["Severity", report.severity],
                ["Confidence", report.confidence],
                ["Hypotheses", String(report.hypothesis_count)],
              ].map(([label, value]) => (
                <div key={label} className="border-b border-forge-border py-5 md:border-b-0 md:border-r md:px-5 md:first:pl-0 md:last:border-r-0">
                  <p className="text-[9px] uppercase tracking-[0.14em] text-forge-muted">{label}</p>
                  <p className="mt-2 font-mono text-[13px] capitalize text-forge-text">{value}</p>
                </div>
              ))}
            </div>

            <div className={`grid border-b border-forge-border sm:grid-cols-2 ${
              activityMetrics.length > 3 ? "lg:grid-cols-5" : "lg:grid-cols-3"
            }`}>
              {activityMetrics.map(([label, value]) => (
                <div key={label} className="border-b border-forge-border py-4 sm:border-r sm:px-4 sm:first:pl-0 sm:last:border-r-0">
                  <p className="text-[9px] uppercase tracking-[0.14em] text-forge-muted">{label}</p>
                  <p className="mt-2 break-words font-mono text-[10px] text-forge-text">{value}</p>
                </div>
              ))}
            </div>

            <div className="grid gap-8 py-7 lg:grid-cols-[1fr_300px]">
              <section>
                <p className="text-[9px] uppercase tracking-[0.16em] text-forge-gold">Observed facts</p>
                <div className="mt-3 space-y-2">
                  {(report.observed_facts || []).map((fact) => (
                    <p key={fact} className="border-l border-forge-gold/40 pl-3 text-[11px] leading-4 text-forge-text">{fact}</p>
                  ))}
                </div>

                {(report.events || []).length > 0 && (
                  <>
                    <p className="mt-7 text-[9px] uppercase tracking-[0.16em] text-forge-gold">Security events</p>
                    <div className="mt-3 divide-y divide-forge-border border-y border-forge-border">
                      {report.events.map((event, index) => (
                        <div key={`${event.timestamp}-${index}`} className="grid gap-2 py-3 sm:grid-cols-[150px_1fr]">
                          <div className="font-mono text-[9px] text-forge-muted">
                            {event.timestamp || "Timestamp unavailable"}
                          </div>
                          <div>
                            <p className="font-mono text-[10px] text-forge-text">
                              {[event.host, event.service, event.source_ip, event.username, event.outcome].filter(Boolean).join(" · ")}
                            </p>
                            <p className="mt-1 text-[10px] leading-4 text-forge-muted">{event.raw}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                )}

                <p className="text-[9px] uppercase tracking-[0.16em] text-forge-gold">Evidence</p>
                {investigation.result.evidence.length === 0 ? (
                  <p className="mt-3 text-xs leading-5 text-forge-muted">No indicators were extracted from the submitted evidence.</p>
                ) : (
                  <div className="mt-3 divide-y divide-forge-border border-y border-forge-border">
                    {investigation.result.evidence.map((item, index) => (
                      <div key={`${item.type}-${item.value}-${index}`} className="grid grid-cols-[90px_1fr] gap-4 py-3">
                        <span className="font-mono text-[9px] uppercase text-forge-gold">{item.type}</span>
                        <div>
                          <p className="break-all font-mono text-[11px] text-forge-text">{item.value}</p>
                          <p className="mt-1 text-[10px] text-forge-muted">{item.provenance}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <p className="mt-7 text-[9px] uppercase tracking-[0.16em] text-forge-gold">Recommendations</p>
                <div className="mt-3 divide-y divide-forge-border border-y border-forge-border">
                  {report.recommendations.map((recommendation, index) => (
                    <div key={recommendation} className="flex gap-3 py-3 text-xs leading-5 text-forge-text">
                      <span className="font-mono text-[9px] text-forge-muted">{String(index + 1).padStart(2, "0")}</span>
                      <span>{recommendation}</span>
                    </div>
                  ))}
                </div>
              </section>

              <aside>
                {(report.hypotheses || []).length > 0 && (
                  <>
                    <p className="text-[9px] uppercase tracking-[0.16em] text-forge-gold">Hypotheses</p>
                    <div className="mt-3 space-y-3">
                      {report.hypotheses.map((hypothesis) => (
                        <div key={hypothesis.pattern} className="border-l border-forge-gold/40 pl-3">
                          <p className="text-[11px] font-medium text-forge-text">{hypothesis.pattern}</p>
                          <p className="mt-1 text-[10px] leading-4 text-forge-muted">{hypothesis.basis}</p>
                          {hypothesis.not_confirmed && (
                            <p className="mt-1 text-[10px] leading-4 text-forge-amber">{hypothesis.not_confirmed}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </>
                )}

                <p className={`text-[9px] uppercase tracking-[0.16em] text-forge-amber ${(report.hypotheses || []).length > 0 ? "mt-7" : ""}`}>Uncertainty</p>
                {report.uncertainty.length === 0 ? (
                  <p className="mt-3 text-xs leading-5 text-forge-muted">No explicit uncertainty was recorded.</p>
                ) : (
                  <div className="mt-3 space-y-2">
                    {report.uncertainty.map((item) => (
                      <p key={item} className="border-l border-forge-amber/50 pl-3 text-[11px] leading-4 text-forge-muted">
                        {item}
                      </p>
                    ))}
                  </div>
                )}

                <p className="mt-7 text-[9px] uppercase tracking-[0.16em] text-forge-muted">Agent execution</p>
                <div className="mt-3 space-y-2">
                  {investigation.result.agent_executions.map((execution) => (
                    <div key={execution.agent} className="flex items-center justify-between border-b border-forge-border py-2">
                      <span className="max-w-[180px] truncate text-[10px] text-forge-text">{execution.agent}</span>
                      <span className="font-mono text-[8px] uppercase text-forge-muted">{execution.status}</span>
                    </div>
                  ))}
                </div>
              </aside>
            </div>
          </>
        )}
        {!loading && investigation && !report && (
          <div className="border-b border-forge-border py-10">
            <p className="text-sm text-forge-text">Report not generated</p>
            <p className="mt-2 text-xs text-forge-muted">
              The investigation has not produced a report payload. Open the workflow to inspect the agent execution state.
            </p>
          </div>
        )}
      </main>
    </AppLayout>
  );
}
