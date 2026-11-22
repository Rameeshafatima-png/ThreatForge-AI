import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import { AppLayout } from "../components/AppLayout";
import { apiUrl } from "../lib/api";

type RecordSummary = {
  id: string;
  prompt: string;
  status: string;
  report_status: string;
  created_at: string;
};

export default function History() {
  const router = useRouter();
  const [records, setRecords] = useState<RecordSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    fetch(apiUrl("/investigations"), { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("Investigation history could not be loaded");
        return response.json();
      })
      .then((result) => setRecords(result))
      .catch((reason) => {
        if (reason.name !== "AbortError") {
          setError(reason instanceof Error ? reason.message : "Investigation history could not be loaded");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, []);

  return (
    <AppLayout>
      <header className="page-header">
        <div className="min-w-0">
          <p className="text-[11px] uppercase tracking-[0.18em] text-forge-muted">Casebook</p>
          <h1 className="mt-0.5 text-sm font-medium">Investigations</h1>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/" className="button-primary">New investigation</Link>
          <span className="hidden font-mono text-[10px] text-forge-muted sm:inline">
            {String(records.length).padStart(2, "0")} RECORDS
          </span>
        </div>
      </header>
      <main className="page-content page-enter">
        <div className="mb-5 max-w-2xl">
          <p className="text-sm leading-6 text-forge-muted">
            Open any case to inspect its agent execution, evidence and report.
          </p>
        </div>
        <div className="grid grid-cols-[minmax(0,1fr)_86px] border-b border-forge-border pb-3 text-[9px] uppercase tracking-[0.14em] text-forge-muted sm:grid-cols-[minmax(0,1fr)_120px_160px]">
          <span>Investigation</span>
          <span>Status</span>
          <span className="hidden sm:block">Created</span>
        </div>
        {loading ? (
          <div className="state-panel mt-4" role="status">
            <span className="loading-mark" aria-hidden="true" />
            <p className="text-sm text-forge-muted">Loading investigation history...</p>
          </div>
        ) : error ? (
          <div className="state-panel state-panel-error mt-4" role="alert">
            <div>
              <p className="text-sm font-medium">History unavailable</p>
              <p className="mt-2 text-xs text-forge-muted">{error}</p>
            </div>
          </div>
        ) : records.length === 0 ? (
          <div className="state-panel mt-4">
            <div>
              <p className="eyebrow">Casebook empty</p>
              <p className="mt-2 text-sm font-medium">No previous investigations</p>
              <p className="mt-2 text-xs text-forge-muted">Your cases will appear here after submission.</p>
              <Link href="/" className="button-primary mt-5">Start an investigation</Link>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-forge-border">
            {records.map((record) => (
              <button
                key={record.id}
                type="button"
                aria-label={`Open investigation ${record.prompt}`}
                onClick={() => {
                  window.localStorage.setItem("threatforge_active_investigation", record.id);
                  router.push(`/workspace?id=${encodeURIComponent(record.id)}`);
                }}
                className="interactive-row grid w-full grid-cols-[minmax(0,1fr)_86px] items-center gap-3 py-4 text-left sm:grid-cols-[minmax(0,1fr)_120px_160px]"
              >
                <span className="min-w-0 truncate pr-2 text-xs text-forge-text">{record.prompt}</span>
                <span className={`status-pill status-pill-${record.status}`}>{record.status}</span>
                <span className="hidden font-mono text-[9px] text-forge-muted sm:block">
                  {new Date(record.created_at).toLocaleString()}
                </span>
              </button>
            ))}
          </div>
        )}
      </main>
    </AppLayout>
  );
}
