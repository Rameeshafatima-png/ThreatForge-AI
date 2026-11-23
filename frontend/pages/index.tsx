import { CasebookWorkspace } from "../components/CasebookWorkspace";
import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import { apiUrl } from "../lib/api";

type Investigation = {
  id: string;
  prompt: string;
  status: string;
  report_status: string;
};

const examples = [
  { code: "IP", title: "IP Intelligence", detail: "Investigate an IP address", icon: "◎" },
  { code: "URL", title: "URL Analysis", detail: "Inspect suspicious domains", icon: "↗" },
  { code: "HASH", title: "File Analysis", detail: "Check file fingerprints", icon: "⌘" },
  { code: "LOG", title: "Log Intelligence", detail: "Analyze security events", icon: "≋" },
  { code: "INCIDENT", title: "Incident Response", detail: "Investigate an attack", icon: "⌁" },
];

const agents = [
  { no: "01", title: "Triage Agent", detail: "Classifies evidence and identifies investigation priorities.", icon: "◈" },
  { no: "02", title: "Threat Intelligence", detail: "Enriches indicators with external threat intelligence.", icon: "◎" },
  { no: "03", title: "Log Analysis", detail: "Examines events, logs and suspicious activity.", icon: "≋" },
  { no: "04", title: "Threat Correlation", detail: "Connects evidence and identifies attack patterns.", icon: "⌘" },
  { no: "05", title: "Risk Assessment", detail: "Evaluates severity and generates reports.", icon: "↗" },
];

export default function CommandCenter() {
  const router = useRouter();

  const [prompt, setPrompt] = useState("");
  const [backendStatus, setBackendStatus] = useState<
    "checking" | "ready" | "offline"
  >("checking");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const [recent, setRecent] = useState<Investigation[]>([]);
  const [recentLoading, setRecentLoading] = useState(true);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<any>(null);
  useEffect(() => {
    const controller = new AbortController();

    fetch(apiUrl("/health"), { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("Backend unavailable");
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
        if (!response.ok) throw new Error("Could not load investigations");
        return response.json();
      })
      .then((records) => setRecent(records))
      .catch((error) => {
        if (error.name !== "AbortError") setRecent([]);
      })
      .finally(() => {
        if (!controller.signal.aborted) setRecentLoading(false);
      });

    return () => controller.abort();
  }, []);

  useEffect(() => {
    const elements = document.querySelectorAll(".reveal");

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12 }
    );

    elements.forEach((element) => observer.observe(element));

    return () => observer.disconnect();
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();

    if (!prompt.trim()) return;

    setSubmitting(true);
    setMessage("");

    try {
      const response = await fetch(apiUrl("/investigations"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt }),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => null);
        throw new Error(data?.detail || "Investigation could not be started.");
      }

      const record = await response.json();

window.localStorage.setItem(
  "threatforge_active_investigation",
  record.id
);

const detailResponse = await fetch(
  apiUrl(`/investigations/${encodeURIComponent(record.id)}`)
);

if (!detailResponse.ok) {
  throw new Error("Investigation completed but results could not be loaded.");
}

const fullRecord = await detailResponse.json();

setAnalysis(fullRecord);
setSelectedCaseId(record.id);
setRecent((previous) => [
  record,
  ...previous.filter((item) => item.id !== record.id),
]);
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : "Unable to connect to ThreatForge backend."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="tf-home">

      {/* BACKGROUND */}
      <div className="tf-background" aria-hidden="true">
        <div className="ambient ambient-one" />
        <div className="ambient ambient-two" />
        <div className="grid-overlay" />
        <div className="particle particle-one" />
        <div className="particle particle-two" />
        <div className="particle particle-three" />
        <div className="particle particle-four" />
      </div>

      {/* NAVIGATION */}
      <nav className="tf-navbar">
        <Link href="/" className="tf-brand">
          <span className="brand-logo">TF</span>
          <span>ThreatForge<span className="brand-dot">.</span></span>
        </Link>

        <div className="nav-center">
          <Link href="/">Home</Link>
          <a href="#intelligence">Intelligence</a>
          <a href="#agents">AI Agents</a>
          <button
  type="button"
  onClick={() =>
    document.querySelector(".casebook-section")?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    })
  }
>
  Casebook
</button>
        </div>

        <div className="nav-actions">
          <div className="connection">
            <span className={`status-dot ${backendStatus}`} />
            {backendStatus === "ready"
              ? "System online"
              : backendStatus === "offline"
                ? "Backend offline"
                : "Connecting"}
          </div>
          <button
  type="button"
  className="nav-login"
  onClick={() =>
    document.querySelector(".casebook-section")?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    })
  }
>
  Workspace
</button>
        </div>
      </nav>

      {/* HERO */}
      <section className="hero-section">

        <div className="hero-badge">
          <span className="live-pulse" />
          AUTONOMOUS CYBERSECURITY INTELLIGENCE
        </div>

        <div className="hero-heading">
          <h1>
            See beyond the
            <br />
            <span className="gradient-text">threat landscape.</span>
          </h1>

          <p>
            Intelligence-driven investigations.
            <br />
            Five specialized AI agents. One unified security platform.
          </p>
        </div>

        <div className="hero-actions">
          <a href="#investigate" className="primary-btn">
            Start Investigation <span>↗</span>
          </a>
          <a href="#intelligence" className="secondary-btn">
            Explore Platform <span>↓</span>
          </a>
        </div>

        {/* CYBER GLOBE */}
        <div className="globe-stage">
          <div className="globe-orbit orbit-one" />
          <div className="globe-orbit orbit-two" />
          <div className="globe-orbit orbit-three" />

          <div className="globe">
            <div className="globe-shine" />
            <div className="globe-grid" />
            <div className="globe-land" />
            <div className="globe-scan" />
            <div className="globe-center" />
          </div>

          <div className="globe-light light-one" />
          <div className="globe-light light-two" />

          <div className="floating-card float-left">
            <span className="mini-label">THREAT DETECTION</span>
            <strong>ACTIVE MONITORING</strong>
            <span className="mini-green">● Intelligence ready</span>
          </div>

          <div className="floating-card float-right">
            <span className="mini-label">AI AGENTS</span>
            <strong>05 SPECIALISTS</strong>
            <span className="mini-green">● Workflow enabled</span>
          </div>

          <div className="floating-card float-bottom">
            <span className="mini-label">INVESTIGATION ENGINE</span>
            <strong>LangGraph Orchestration</strong>
            <span className="mini-green">SYSTEM READY</span>
          </div>
        </div>

        <div className="hero-bottom-label">
          <span>THREATFORGE INTELLIGENCE ENGINE</span>
          <span>BUILT FOR SECURITY ANALYSTS</span>
        </div>
      </section>

      {/* STATS */}
      <section className="stats-strip reveal">
        <div>
          <strong>05</strong>
          <span>Specialized AI Agents</span>
        </div>
        <div>
          <strong>01</strong>
          <span>Unified Investigation</span>
        </div>
        <div>
          <strong>24/7</strong>
          <span>Intelligence Workflow</span>
        </div>
        <div>
          <strong>AI</strong>
          <span>Powered Analysis</span>
        </div>
      </section>

      {/* INTELLIGENCE */}
      <section className="content-section" id="intelligence">

        <div className="section-heading reveal">
          <span className="section-kicker">01 / INTELLIGENCE PLATFORM</span>
          <h2>
            Everything you need.
            <br />
            <span className="gradient-text">One security ecosystem.</span>
          </h2>
          <p>
            Transform raw security evidence into structured,
            actionable intelligence.
          </p>
        </div>

        <div className="feature-grid reveal">
          {examples.map((item, index) => (
            <button
              type="button"
              className="feature-card"
              key={item.code}
              onClick={() =>
                setPrompt(item.title + ": ")
              }
            >
              <div className="feature-top">
                <span className="feature-icon">{item.icon}</span>
                <span className="feature-number">
                  0{index + 1}
                </span>
              </div>

              <h3>{item.title}</h3>
              <p>{item.detail}</p>
              <span className="feature-arrow">↗</span>
            </button>
          ))}
        </div>
      </section>

      {/* INVESTIGATION */}
      <section className="investigation-section" id="investigate">

        <div className="investigation-copy reveal">
          <span className="section-kicker">02 / INVESTIGATION CONSOLE</span>
          <h2>
            Every threat has
            <br />
            a <span className="gradient-text">story.</span>
          </h2>
          <p>
            Submit an indicator, suspicious URL, security log,
            or incident description. Let ThreatForge investigate
            the evidence through its coordinated AI workflow.
          </p>
        </div>

        <form className="investigation-box reveal" onSubmit={submit}>
          <div className="input-top">
            <span>TF / EVIDENCE INTAKE</span>
            <span className="input-live">
              <span className="live-pulse" /> SECURE SESSION
            </span>
          </div>

          <textarea
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            placeholder="Paste an IP address, suspicious URL, file hash, security logs or describe the incident..."
          />

          <div className="input-bottom">
            <span>ENCRYPTED INVESTIGATION WORKFLOW</span>
            <button
              type="submit"
              disabled={!prompt.trim() || submitting}
              className="primary-btn submit-btn"
            >
              {submitting ? "Running agents..." : "Analyze Threat"}
              <span>↗</span>
            </button>
          </div>
        </form>
                

        {message && (
          <p className="error-message" role="alert">{message}</p>
        )}
      </section>
      {/* INVESTIGATION WORKSPACE */}
      {selectedCaseId && (
  <div id="inline-workspace">
    <CasebookWorkspace selectedId={selectedCaseId} />
  </div>
)}
          
      {/* AI AGENTS */}
      <section className="content-section agents-section" id="agents">

        <div className="section-heading reveal">
          <span className="section-kicker">03 / MULTI-AGENT ARCHITECTURE</span>
          <h2>
            Five agents.
            <br />
            <span className="gradient-text">One intelligence network.</span>
          </h2>
          <p>
            Each specialist contributes a different layer
            of analysis to the investigation.
          </p>
        </div>

        <div className="agent-grid reveal">
          {agents.map((agent) => (
            <div className="agent-card" key={agent.no}>
              <div className="agent-top">
                <span>{agent.no} / AGENT</span>
                <span className="agent-symbol">{agent.icon}</span>
              </div>
              <h3>{agent.title}</h3>
              <p>{agent.detail}</p>
              <div className="agent-line" />
              <span className="agent-status">
                <span className="live-pulse" /> SPECIALIZED MODULE
              </span>
            </div>
          ))}
        </div>
      </section>
      
      {/* RECENT CASEBOOK */}
      <section className="casebook-section reveal">

        <div className="casebook-heading">
          <div>
            <span className="section-kicker">04 / INVESTIGATION RECORDS</span>
            <h2>Recent investigations</h2>
          </div>

          <button
  type="button"
  className="secondary-btn"
  onClick={() =>
    document.getElementById("investigation-console")?.scrollIntoView({
      behavior: "smooth",
    })
  }
>
  View Casebook ↗
</button>
        </div>

        <div className="casebook-list">
          {recentLoading ? (
            <p className="empty-state">Loading investigations...</p>
          ) : recent.length === 0 ? (
            <p className="empty-state">
              No investigations yet. Start your first investigation above.
            </p>
          ) : (
            recent.slice(0, 4).map((record) => (
              <button
                type="button"
                className="case-row"
                key={record.id}
                onClick={() => {
  window.localStorage.setItem(
    "threatforge_active_investigation",
    record.id
  );

  setSelectedCaseId(record.id);

  setTimeout(() => {
    document.getElementById("inline-workspace")?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  }, 100);
}}
              >
                <span className="case-indicator">◈</span>
                <span className="case-prompt">{record.prompt}</span>
              </button>
            ))
          )}
        </div>
      </section>

      {/* FOOTER */}
      <footer className="tf-footer">
        <Link href="/" className="tf-brand">
          <span className="brand-logo">TF</span>
          <span>ThreatForge<span className="brand-dot">.</span></span>
        </Link>

        <span>Autonomous Cybersecurity Intelligence Platform</span>

        <span>© 2026 THREATFORGE</span>
      </footer>

      <style jsx global>{`
        :root {
          --tf-black: #050607;
          --tf-panel: #0b0e10;
          --tf-border: rgba(180, 194, 205, .13);
          --tf-white: #f1f4f5;
          --tf-muted: #929ba3;
          --tf-lime: #c7ff72;
          --tf-blue: #91b8d1;
        }

        html {
          scroll-behavior: smooth;
          background: var(--tf-black);
        }

        body {
          margin: 0;
          background: var(--tf-black) !important;
          color: var(--tf-white);
          font-family: Inter, Arial, sans-serif;
        }

        .tf-home {
          position: relative;
          min-height: 100vh;
          overflow: hidden;
          background: #050607;
          isolation: isolate;
        }

        .tf-home a {
          text-decoration: none;
        }

        .tf-background {
          position: absolute;
          inset: 0;
          z-index: -1;
          pointer-events: none;
          overflow: hidden;
        }

        .grid-overlay {
          position: absolute;
          inset: 0;
          opacity: .17;
          background-image:
            linear-gradient(rgba(160,180,190,.045) 1px, transparent 1px),
            linear-gradient(90deg, rgba(160,180,190,.045) 1px, transparent 1px);
          background-size: 60px 60px;
          mask-image: linear-gradient(to bottom, black, transparent 75%);
        }

        .ambient {
          position: absolute;
          width: 600px;
          height: 600px;
          border-radius: 50%;
          filter: blur(100px);
          animation: ambientMove 14s ease-in-out infinite alternate;
        }

        .ambient-one {
          top: 100px;
          left: 25%;
          background: rgba(133, 164, 186, .10);
        }

        .ambient-two {
          top: 500px;
          right: -200px;
          background: rgba(173, 220, 115, .055);
          animation-delay: -6s;
        }

        .particle {
          position: absolute;
          width: 4px;
          height: 4px;
          border-radius: 50%;
          background: var(--tf-lime);
          box-shadow: 0 0 14px var(--tf-lime);
          animation: particleFloat 7s ease-in-out infinite;
        }

        .particle-one { top: 15%; left: 13%; }
        .particle-two { top: 24%; right: 16%; animation-delay: -2s; }
        .particle-three { top: 65%; left: 8%; animation-delay: -4s; }
        .particle-four { top: 76%; right: 12%; animation-delay: -1s; }

        .tf-navbar {
          position: relative;
          z-index: 10;
          display: flex;
          height: 78px;
          align-items: center;
          justify-content: space-between;
          gap: 20px;
          padding: 0 6%;
          border-bottom: 1px solid var(--tf-border);
          background: rgba(5, 6, 7, .78);
          backdrop-filter: blur(22px);
        }

        .tf-brand {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          color: var(--tf-white);
          font-size: 16px;
          font-weight: 750;
          letter-spacing: -.6px;
        }

        .brand-logo {
          display: grid;
          width: 35px;
          height: 35px;
          place-items: center;
          border-radius: 10px;
          background: linear-gradient(140deg, #d9ff9d, #a4e54b);
          color: #101509;
          font-size: 12px;
          box-shadow: 0 0 24px rgba(199,255,114,.15);
        }

        .brand-dot { color: var(--tf-lime); }

        .nav-center {
          display: flex;
          align-items: center;
          gap: 32px;
        }

        .nav-center a {
          color: #a2aab0;
          font-size: 12px;
          transition: color .25s ease;
        }

        .nav-center a:hover { color: var(--tf-lime); }

        .nav-actions {
          display: flex;
          align-items: center;
          gap: 22px;
        }

        .connection {
          display: flex;
          align-items: center;
          gap: 8px;
          color: var(--tf-muted);
          font-size: 10px;
        }

        .status-dot, .live-pulse {
          width: 7px;
          height: 7px;
          flex-shrink: 0;
          border-radius: 50%;
          background: #888;
        }

        .status-dot.ready {
          background: #b9ed74;
          box-shadow: 0 0 12px #b9ed74;
        }

        .status-dot.offline { background: #ff7070; }
        .status-dot.checking { background: #d8bd78; }

        .nav-login {
          padding: 11px 17px;
          border: 1px solid rgba(199,255,114,.45);
          border-radius: 5px;
          color: var(--tf-lime);
          font-size: 11px;
          transition: .25s ease;
        }

        .nav-login:hover {
          background: var(--tf-lime);
          color: #101509;
          box-shadow: 0 0 25px rgba(199,255,114,.17);
        }

        .hero-section {
          position: relative;
          padding: 88px 20px 25px;
          text-align: center;
        }

        .hero-badge {
          display: inline-flex;
          align-items: center;
          gap: 9px;
          padding: 9px 15px;
          border: 1px solid var(--tf-border);
          border-radius: 30px;
          background: rgba(255,255,255,.025);
          color: #bdc6cc;
          font-size: 9px;
          letter-spacing: 1.8px;
          animation: fadeDown .8s ease both;
        }

        .live-pulse {
          display: inline-block;
          background: var(--tf-lime);
          box-shadow: 0 0 12px var(--tf-lime);
          animation: pulse 2s infinite;
        }

        .hero-heading {
          margin-top: 34px;
          animation: fadeUp 1s ease both;
        }

        .hero-heading h1 {
          margin: 0;
          color: #edf0f2;
          font-size: clamp(43px, 7vw, 84px);
          line-height: 1.02;
          font-weight: 650;
          letter-spacing: -5px;
        }

        .gradient-text {
          background: linear-gradient(100deg, #f4f5f4 5%, #b7c5cc 42%, #c7ff72 100%);
          -webkit-background-clip: text;
          background-clip: text;
          color: transparent;
        }

        .hero-heading p {
          margin: 22px auto 0;
          color: #9ba5ad;
          font-size: 14px;
          line-height: 1.9;
        }

        .hero-actions {
          display: flex;
          justify-content: center;
          flex-wrap: wrap;
          gap: 13px;
          margin-top: 29px;
          animation: fadeUp 1.2s ease both;
        }

        .primary-btn, .secondary-btn {
          display: inline-flex;
          min-height: 43px;
          align-items: center;
          justify-content: center;
          gap: 17px;
          padding: 0 19px;
          border-radius: 5px;
          font-size: 11px;
          font-weight: 650;
          transition: transform .25s ease, box-shadow .25s ease, background .25s ease;
          cursor: pointer;
        }

        .primary-btn {
          border: 1px solid #d4ff91;
          background: linear-gradient(120deg, #d5ff98, #a9e65b);
          color: #101509;
          box-shadow: 0 0 25px rgba(199,255,114,.11);
        }

        .primary-btn:hover:not(:disabled) {
          transform: translateY(-3px);
          box-shadow: 0 9px 32px rgba(199,255,114,.23);
        }

        .secondary-btn {
          border: 1px solid var(--tf-border);
          background: rgba(255,255,255,.025);
          color: #e3e8ea;
        }

        .secondary-btn:hover {
          transform: translateY(-2px);
          border-color: rgba(199,255,114,.5);
          color: var(--tf-lime);
        }

        .globe-stage {
          position: relative;
          display: flex;
          width: min(100%, 760px);
          height: 390px;
          align-items: center;
          justify-content: center;
          margin: 28px auto 0;
          perspective: 1000px;
          animation: fadeUp 1.2s ease both;
        }

        .globe {
          position: relative;
          width: 330px;
          height: 330px;
          overflow: hidden;
          border: 1px solid rgba(168,202,215,.4);
          border-radius: 50%;
          background:
            radial-gradient(circle at 35% 25%, rgba(208,237,244,.22), transparent 24%),
            radial-gradient(circle at 50% 45%, #172b35 0%, #0b171e 48%, #030607 76%);
          box-shadow:
            inset -28px -24px 55px #020405,
            inset 8px 8px 40px rgba(171,216,226,.14),
            0 0 60px rgba(133,190,205,.10),
            0 0 120px rgba(199,255,114,.045);
          animation: globeFloat 7s ease-in-out infinite;
        }

        .globe-shine {
          position: absolute;
          inset: 0;
          border-radius: 50%;
          background: linear-gradient(125deg, rgba(255,255,255,.15), transparent 37%, transparent 65%, rgba(199,255,114,.12));
        }

        .globe-grid {
          position: absolute;
          inset: -15%;
          border-radius: 50%;
          background:
            repeating-linear-gradient(0deg, transparent 0 23px, rgba(157,207,217,.18) 24px, transparent 25px),
            repeating-linear-gradient(90deg, transparent 0 30px, rgba(157,207,217,.13) 31px, transparent 32px);
          mask-image: radial-gradient(ellipse, black 48%, transparent 71%);
          animation: globeRotate 28s linear infinite;
        }

        .globe-land {
          position: absolute;
          inset: 0;
          border-radius: 50%;
          opacity: .58;
          background-image: radial-gradient(circle, #b6e0c0 1px, transparent 1.8px);
          background-size: 9px 9px;
          mask-image:
            radial-gradient(ellipse 25% 15% at 34% 36%, black 55%, transparent 75%),
            radial-gradient(ellipse 24% 30% at 64% 57%, black 52%, transparent 75%),
            radial-gradient(ellipse 10% 18% at 76% 25%, black 45%, transparent 75%);
          mask-composite: add;
        }

        .globe-scan {
          position: absolute;
          top: -15%;
          left: 0;
          width: 100%;
          height: 35%;
          border-bottom: 1px solid rgba(199,255,114,.65);
          background: linear-gradient(to bottom, transparent, rgba(199,255,114,.12));
          filter: blur(2px);
          animation: scan 5s linear infinite;
        }

        .globe-center {
          position: absolute;
          inset: 45%;
          border-radius: 50%;
          background: #d6ff9b;
          box-shadow: 0 0 25px #c7ff72, 0 0 65px rgba(199,255,114,.65);
          animation: pulse 3s infinite;
        }

        .globe-orbit {
          position: absolute;
          width: 430px;
          height: 145px;
          border: 1px solid rgba(164,204,215,.23);
          border-radius: 50%;
          transform: rotate(-23deg);
        }

        .orbit-two {
          width: 490px;
          height: 175px;
          transform: rotate(22deg);
          border-color: rgba(199,255,114,.18);
        }

        .orbit-three {
          width: 540px;
          height: 205px;
          transform: rotate(65deg);
          border-color: rgba(164,204,215,.12);
        }

        .globe-light {
          position: absolute;
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: var(--tf-lime);
          box-shadow: 0 0 18px var(--tf-lime);
        }

        .light-one { top: 26%; left: 27%; }
        .light-two { bottom: 24%; right: 24%; }

        .floating-card {
          position: absolute;
          z-index: 2;
          display: flex;
          min-width: 170px;
          flex-direction: column;
          gap: 9px;
          padding: 15px;
          border: 1px solid rgba(183,207,215,.22);
          border-radius: 7px;
          background: rgba(9,15,19,.79);
          box-shadow: 0 15px 45px rgba(0,0,0,.38), inset 0 1px 0 rgba(255,255,255,.05);
          text-align: left;
          backdrop-filter: blur(14px);
          animation: cardFloat 5s ease-in-out infinite;
        }

        .float-left { top: 26%; left: 1%; }
        .float-right { top: 31%; right: 1%; animation-delay: -2s; }
        .float-bottom {
          bottom: 0;
          left: 50%;
          min-width: 210px;
          transform: translateX(-50%);
          animation-delay: -3s;
        }

        .mini-label {
          color: #8e9da5;
          font-size: 8px;
          letter-spacing: 1.4px;
        }

        .floating-card strong {
          font-size: 11px;
          letter-spacing: .3px;
        }

        .mini-green {
          color: var(--tf-lime);
          font-size: 9px;
        }

        .hero-bottom-label {
          display: flex;
          max-width: 900px;
          justify-content: space-between;
          margin: 12px auto 0;
          padding: 15px 0;
          border-top: 1px solid var(--tf-border);
          color: #69747b;
          font-size: 8px;
          letter-spacing: 1.5px;
        }

        .stats-strip {
          display: grid;
          max-width: 1080px;
          grid-template-columns: repeat(4, 1fr);
          margin: 30px auto 100px;
          border: 1px solid var(--tf-border);
          border-radius: 8px;
          background: rgba(255,255,255,.018);
        }

        .stats-strip div {
          display: flex;
          flex-direction: column;
          gap: 8px;
          padding: 25px;
          border-right: 1px solid var(--tf-border);
        }

        .stats-strip div:last-child { border: 0; }

        .stats-strip strong {
          color: var(--tf-white);
          font-size: 27px;
          font-weight: 600;
        }

        .stats-strip span {
          color: var(--tf-muted);
          font-size: 10px;
        }

        .content-section {
          max-width: 1080px;
          margin: 0 auto;
          padding: 30px 20px 100px;
          scroll-margin-top: 90px;
        }

        .section-kicker {
          color: var(--tf-lime);
          font-family: monospace;
          font-size: 9px;
          letter-spacing: 1.7px;
        }

        .section-heading h2,
        .investigation-copy h2 {
          margin: 20px 0 14px;
          font-size: clamp(32px, 5vw, 53px);
          font-weight: 550;
          line-height: 1.13;
          letter-spacing: -2px;
        }

        .section-heading > p,
        .investigation-copy > p {
          max-width: 520px;
          color: var(--tf-muted);
          font-size: 12px;
          line-height: 1.9;
        }

        .feature-grid {
          display: grid;
          grid-template-columns: repeat(3, minmax(0,1fr));
          gap: 15px;
          margin-top: 43px;
        }

        .feature-card {
          position: relative;
          min-height: 180px;
          padding: 21px;
          overflow: hidden;
          border: 1px solid var(--tf-border);
          border-radius: 7px;
          background: linear-gradient(145deg, rgba(255,255,255,.035), rgba(255,255,255,.008));
          color: var(--tf-white);
          text-align: left;
          cursor: pointer;
          transition: transform .3s ease, border-color .3s ease, box-shadow .3s ease;
        }

        .feature-card:hover {
          transform: translateY(-7px);
          border-color: rgba(199,255,114,.4);
          box-shadow: 0 15px 45px rgba(0,0,0,.25), 0 0 25px rgba(199,255,114,.055);
        }

        .feature-top {
          display: flex;
          justify-content: space-between;
        }

        .feature-icon {
          color: var(--tf-lime);
          font-size: 23px;
        }

        .feature-number {
          color: #647078;
          font-family: monospace;
          font-size: 10px;
        }

        .feature-card h3 {
          margin: 24px 0 8px;
          font-size: 14px;
          font-weight: 550;
        }

        .feature-card p {
          color: var(--tf-muted);
          font-size: 10px;
          line-height: 1.7;
        }

        .feature-arrow {
          position: absolute;
          right: 20px;
          bottom: 19px;
          color: var(--tf-lime);
          opacity: .5;
          transition: opacity .2s, transform .2s;
        }

        .feature-card:hover .feature-arrow {
          opacity: 1;
          transform: translate(3px,-3px);
        }

        .investigation-section {
          display: grid;
          max-width: 1080px;
          grid-template-columns: .8fr 1.2fr;
          align-items: center;
          gap: 55px;
          margin: 0 auto;
          padding: 80px 20px 110px;
          border-top: 1px solid var(--tf-border);
          border-bottom: 1px solid var(--tf-border);
          scroll-margin-top: 70px;
        }

        .investigation-copy h2 { font-size: 46px; }

        .investigation-box {
          padding: 23px;
          border: 1px solid rgba(199,255,114,.22);
          border-radius: 9px;
          background: linear-gradient(145deg, rgba(199,255,114,.035), transparent 55%), #0a0e10;
          box-shadow: 0 20px 70px rgba(0,0,0,.3);
        }

        .input-top, .input-bottom {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }

        .input-top {
          padding-bottom: 16px;
          border-bottom: 1px solid var(--tf-border);
          color: var(--tf-lime);
          font-family: monospace;
          font-size: 9px;
          letter-spacing: 1px;
        }

        .input-live {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #89949a;
          font-size: 8px;
        }

        .investigation-box textarea {
          width: 100%;
          min-height: 165px;
          padding: 20px 0;
          resize: vertical;
          border: 0;
          outline: none;
          background: transparent;
          color: white;
          font-family: inherit;
          font-size: 13px;
          line-height: 1.8;
        }

        .investigation-box textarea::placeholder { color: #657078; }

        .input-bottom {
          padding-top: 15px;
          border-top: 1px solid var(--tf-border);
        }

        .input-bottom > span {
          color: #75818a;
          font-family: monospace;
          font-size: 8px;
        }

        .submit-btn:disabled {
          cursor: not-allowed;
          opacity: .4;
        }

        .error-message {
          grid-column: 2;
          color: #ff8888;
          font-size: 11px;
        }

        .agents-section { padding-top: 110px; }

        .agent-grid {
          display: grid;
          grid-template-columns: repeat(5, minmax(0,1fr));
          gap: 12px;
          margin-top: 42px;
        }

        .agent-card {
          min-height: 195px;
          padding: 17px;
          border: 1px solid var(--tf-border);
          border-radius: 7px;
          background: rgba(255,255,255,.018);
          transition: transform .3s, border-color .3s, background .3s;
        }

        .agent-card:hover {
          transform: translateY(-5px);
          border-color: rgba(199,255,114,.36);
          background: rgba(199,255,114,.025);
        }

        .agent-top {
          display: flex;
          align-items: center;
          justify-content: space-between;
          color: #77848b;
          font-family: monospace;
          font-size: 8px;
        }

        .agent-symbol {
          color: var(--tf-lime);
          font-size: 19px;
        }

        .agent-card h3 {
          margin-top: 27px;
          font-size: 12px;
          font-weight: 550;
        }

        .agent-card p {
          min-height: 55px;
          color: var(--tf-muted);
          font-size: 9px;
          line-height: 1.7;
        }

        .agent-line {
          height: 1px;
          margin: 14px 0;
          background: var(--tf-border);
        }

        .agent-status {
          display: flex;
          align-items: center;
          gap: 7px;
          color: #89958b;
          font-family: monospace;
          font-size: 7px;
          letter-spacing: .5px;
        }

        .casebook-section {
          max-width: 1080px;
          margin: 0 auto;
          padding: 70px 20px 100px;
        }

        .casebook-heading {
          display: flex;
          align-items: end;
          justify-content: space-between;
          gap: 20px;
          margin-bottom: 25px;
        }

        .casebook-heading h2 {
          margin: 12px 0 0;
          font-size: 25px;
          font-weight: 550;
        }

        .casebook-list {
          border-top: 1px solid var(--tf-border);
        }

        .case-row {
          display: flex;
          width: 100%;
          align-items: center;
          gap: 17px;
          padding: 17px 10px;
          border: 0;
          border-bottom: 1px solid var(--tf-border);
          background: transparent;
          color: var(--tf-white);
          text-align: left;
          cursor: pointer;
          transition: background .2s;
        }

        .case-row:hover { background: rgba(199,255,114,.035); }

        .case-indicator { color: var(--tf-lime); }
        .case-prompt { flex: 1; overflow: hidden; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
        .case-status { color: #a4bb8b; font-family: monospace; font-size: 9px; }
        .empty-state { padding: 28px 5px; color: var(--tf-muted); font-size: 11px; }

        .tf-footer {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 20px;
          padding: 28px 6%;
          border-top: 1px solid var(--tf-border);
          color: #79848b;
          font-size: 9px;
        }

        .reveal {
          opacity: 0;
          transform: translateY(28px);
          transition: opacity .8s ease, transform .8s ease;
        }

        .reveal.visible {
          opacity: 1;
          transform: translateY(0);
        }

        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(24px); }
          to { opacity: 1; transform: translateY(0); }
        }

        @keyframes fadeDown {
          from { opacity: 0; transform: translateY(-15px); }
          to { opacity: 1; transform: translateY(0); }
        }

        @keyframes globeFloat {
          0%, 100% { transform: translateY(0) rotate(-2deg); }
          50% { transform: translateY(-12px) rotate(2deg); }
        }

        @keyframes globeRotate {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        @keyframes scan {
          from { top: -30%; }
          to { top: 110%; }
        }

        @keyframes cardFloat {
          0%, 100% { margin-top: 0; }
          50% { margin-top: -12px; }
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: .55; transform: scale(.8); }
        }

        @keyframes particleFloat {
          0%, 100% { transform: translateY(0); opacity: .3; }
          50% { transform: translateY(-35px); opacity: 1; }
        }

        @keyframes ambientMove {
          from { transform: translate(0,0) scale(1); }
          to { transform: translate(50px,-40px) scale(1.2); }
        }

        /* Hide old sidebar on the redesigned homepage */
        .desktop-sidebar,
        .mobile-navigation {
          display: none !important;
        }

        @media (min-width: 768px) {
          main.min-h-screen.md\\:ml-\\[224px\\] {
            margin-left: 0 !important;
          }
        }

        @media (max-width: 900px) {
          .nav-center { gap: 14px; }
          .nav-center a { font-size: 10px; }
          .agent-grid { grid-template-columns: repeat(3,1fr); }
          .investigation-section { gap: 25px; }
          .stats-strip { margin-right: 20px; margin-left: 20px; }
        }

        @media (max-width: 650px) {
          .tf-navbar { height: auto; min-height: 68px; flex-wrap: wrap; padding: 14px 18px; }
          .nav-center { order: 3; width: 100%; justify-content: space-between; padding: 8px 0 2px; }
          .nav-actions { gap: 10px; }
          .connection { font-size: 9px; }
          .hero-section { padding-top: 65px; }
          .hero-heading h1 { letter-spacing: -2.5px; }
          .hero-heading p { font-size: 12px; }
          .globe-stage { height: 340px; transform: scale(.88); margin: 12px auto -5px; width: 112%; left: -6%; }
          .globe { width: 260px; height: 260px; }
          .globe-orbit { width: 340px; height: 120px; }
          .orbit-two { width: 390px; height: 140px; }
          .orbit-three { width: 420px; height: 160px; }
          .floating-card { min-width: 130px; padding: 10px; }
          .floating-card strong { font-size: 9px; }
          .float-left { left: 0; }
          .float-right { right: 0; }
          .float-bottom { min-width: 170px; }
          .hero-bottom-label { font-size: 7px; gap: 10px; }
          .stats-strip { grid-template-columns: repeat(2,1fr); }
          .stats-strip div:nth-child(2) { border-right: 0; }
          .stats-strip div:nth-child(-n+2) { border-bottom: 1px solid var(--tf-border); }
          .stats-strip div { padding: 18px; }
          .feature-grid { grid-template-columns: repeat(2,minmax(0,1fr)); }
          .investigation-section { grid-template-columns: 1fr; padding-top: 60px; padding-bottom: 65px; }
          .investigation-copy h2 { font-size: 39px; }
          .agent-grid { grid-template-columns: repeat(2,minmax(0,1fr)); }
          .casebook-heading { align-items: start; flex-direction: column; }
          .tf-footer { flex-direction: column; align-items: start; }
          .input-bottom { align-items: start; flex-direction: column; }
          .input-bottom .primary-btn { width: 100%; }
          .error-message { grid-column: 1; }
        }

        @media (max-width: 380px) {
          .feature-grid, .agent-grid { grid-template-columns: 1fr; }
          .connection { display: none; }
          .hero-badge { font-size: 7px; letter-spacing: 1px; }
        }

        @media (prefers-reduced-motion: reduce) {
          *, *::before, *::after {
            animation-duration: .01ms !important;
            animation-iteration-count: 1 !important;
            scroll-behavior: auto !important;
            transition-duration: .01ms !important;
          }
          .reveal { opacity: 1; transform: none; }
        }
      `}</style>
    </main>
  );
}
