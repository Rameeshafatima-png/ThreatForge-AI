import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/router";
import { AppLayout } from "../components/AppLayout";
import { apiUrl } from "../lib/api";

const examples = [
  { kind: "IP", placeholder: "IPv4 or IPv6 address" },
  { kind: "URL", placeholder: "Domain or full URL" },
  { kind: "FILE HASH", placeholder: "MD5, SHA-1 or SHA-256" },
  { kind: "SECURITY LOG", placeholder: "Paste event records" },
  { kind: "INCIDENT", placeholder: "Describe what happened" },
];

export default function CommandCenter() {
  const router = useRouter();
  const [prompt, setPrompt] = useState("");
  const [backendStatus, setBackendStatus] = useState<"checking" | "ready" | "offline">("checking");
  const [submissionMessage, setSubmissionMessage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [recent, setRecent] = useState<Array<{ id: string; prompt: string; status: string; report_status: string }>>([]);
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

  return (
    <AppLayout>
      <header className="flex h-16 items-center justify-between border-b border-forge-border px-6 md:px-8">
        <div>
          <p className="text-[10px] font-medium uppercase tracking-[0.18em] text-forge-muted">Operations</p>
          <p className="mt-0.5 text-[13px] font-medium">Command Center</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-forge-muted" role="status">
          <span className={`h-1.5 w-1.5 rounded-full ${
            backendStatus === "ready"
              ? "bg-forge-gold"
              : backendStatus === "offline"
                ? "bg-forge-red"
                : "bg-forge-muted"
          }`} />
          {backendStatus === "ready"
            ? "Backend ready"
            : backendStatus === "offline"
              ? "Backend offline"
              : "Checking backend"}
        </div>
      </header>
      <div className="command-page mx-auto max-w-[1120px] px-6 pb-10 pt-8 md:px-8 md:pt-12">
        <div className="mb-6 max-w-[780px]">
          <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-forge-gold">Investigation intake</p>
          <h1 className="pixel-heading heading-reveal max-w-[720px] text-[38px] font-medium leading-[0.98] md:text-[52px]">
            <span className="pixel-heading-gold">See the threat.</span><br />
            <span className="text-[#aaa497]">Understand the evidence.</span>
          </h1>
          <p className="mt-4 max-w-[620px] text-[13px] leading-5 text-forge-muted">
            Autonomous investigation across security signals, logs and threat intelligence.
          </p>
        </div>
        <form onSubmit={submit} className="command-form group rounded-[10px] border border-[#37382f] p-2 transition focus-within:border-[#76684b]">
          <textarea
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            placeholder="Paste an indicator, security log, or describe the incident..."
            className="min-h-[148px] w-full resize-none border-0 bg-transparent px-4 py-4 text-[16px] leading-7 text-forge-text outline-none placeholder:text-[#66685f]"
          />
          <div className="flex items-center justify-between px-2 pb-2">
            <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.12em] text-forge-muted">
              <span className="font-mono text-forge-gold">TF</span>
              Evidence intake
            </div>
            <button type="submit" disabled={!prompt.trim() || submitting} className="investigation-start h-10 rounded-md bg-forge-gold px-4 text-sm font-semibold text-[#17140d] disabled:cursor-not-allowed disabled:opacity-35">
              {submitting ? "Running agents..." : "Start investigation"} <span className="ml-2 opacity-60">↵</span>
            </button>
          </div>
        </form>
        {submissionMessage && (
          <p className="mt-3 text-xs text-forge-muted" role="status">
            {submissionMessage}
          </p>
        )}
        <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          {examples.map((example) => (
            <button
              key={example.kind}
              type="button"
              onClick={() => setPrompt(example.placeholder + ": ")}
              className="interactive-card group flex min-h-[64px] items-center gap-3 rounded-md border border-forge-border bg-forge-bg px-3 text-left transition hover:border-[#51493a] hover:bg-forge-surface"
            >
              <span className="font-mono text-[9px] text-forge-gold">{example.kind}</span>
              <span className="min-w-0">
                <span className="block text-[11px] leading-4 text-forge-muted">{example.placeholder}</span>
              </span>
            </button>
          ))}
        </div>
        <section className="mt-8">
          <div className="mb-4 flex items-end justify-between border-b border-forge-border pb-3">
            <div>
              <p className="text-[11px] uppercase tracking-[0.16em] text-forge-muted">Casebook</p>
              <h2 className="mt-1 text-[15px] font-medium">Recent investigations</h2>
            </div>
            <span className="font-mono text-[11px] text-forge-muted">{String(recent.length).padStart(2, "0")} RECORDS</span>
          </div>
          {recentLoading ? (
          <div className="min-h-[92px] py-5 text-xs text-forge-muted" role="status">
            Loading recent investigations...
          </div>
          ) : recentError ? (
          <div className="min-h-[92px] py-5 text-xs text-forge-red" role="status">
            {recentError}
          </div>
          ) : recent.length === 0 ? (
          <div className="flex min-h-[92px] items-center justify-between px-1 py-4">
            <div>
              <p className="text-sm text-forge-text">No investigations in this workspace</p>
              <p className="mt-1.5 max-w-[440px] text-xs leading-5 text-forge-muted">Submit evidence above to begin a real LangGraph investigation.</p>
            </div>
            <span className="hidden font-mono text-[11px] text-[#5f6158] sm:block">STANDING BY</span>
          </div>
          ) : (
          <div className="divide-y divide-forge-border">
            {recent.slice(0, 3).map((record) => (
              <button
                key={record.id}
                type="button"
                onClick={() => {
                  window.localStorage.setItem("threatforge_active_investigation", record.id);
                  router.push(`/workspace?id=${encodeURIComponent(record.id)}`);
                }}
                className="interactive-row flex w-full items-center justify-between py-3 text-left"
              >
                <span className="max-w-[70%] truncate text-xs text-forge-text">{record.prompt}</span>
                <span className="font-mono text-[9px] uppercase text-forge-muted">{record.status}</span>
              </button>
            ))}
          </div>
          )}
        </section>
        <section className="mt-5 border-t border-forge-border pt-4">
          <div className="flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-[0.12em] text-forge-muted">
            <span className="text-forge-gold">Workflow</span>
            <span>Input</span><span className="text-[#5f5d55]">→</span>
            <span>Triage</span><span className="text-[#5f5d55]">→</span>
            <span>Intelligence</span><span className="text-[#5f5d55]">+</span>
            <span>Logs</span><span className="text-[#5f5d55]">→</span>
            <span>Detection</span><span className="text-[#5f5d55]">→</span>
            <span>Risk & Report</span>
          </div>
        </section>
      </div>
    </AppLayout>
  );
}
