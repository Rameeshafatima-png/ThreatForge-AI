import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";

const navigation = [
  { label: "New investigation", href: "/", glyph: "＋", number: "01" },
  { label: "Workspace", href: "/workspace", glyph: "⌁", number: "02" },
  { label: "Casebook", href: "/history", glyph: "▤", number: "03" },
  { label: "Report", href: "/report", glyph: "▧", number: "04" },
];

export function Sidebar() {
  const router = useRouter();
  const [activeId, setActiveId] = useState("");

  useEffect(() => {
    const queryId = typeof router.query.id === "string" ? router.query.id : "";
    const storedId = window.localStorage.getItem("threatforge_active_investigation") || "";
    const currentId = queryId || storedId;
    setActiveId(currentId);
    if (queryId) window.localStorage.setItem("threatforge_active_investigation", queryId);
  }, [router.asPath, router.query.id]);

  const hrefFor = (item: (typeof navigation)[number]) => {
    if ((item.label === "Workspace" || item.label === "Report") && activeId) {
      return `${item.href}?id=${encodeURIComponent(activeId)}`;
    }
    return item.href;
  };

  const isActive = (item: (typeof navigation)[number]) => {
    if (item.label === "New investigation") return router.pathname === "/";
    return router.pathname === item.href;
  };

  const navLinks = (mobile = false) => navigation.map((item) => {
    const active = isActive(item);
    return (
      <Link
        key={item.label}
        href={hrefFor(item)}
        aria-current={active ? "page" : undefined}
        className={`nav-link ${mobile ? "nav-link-mobile" : ""} ${active ? "nav-link-active" : ""}`}
      >
        <span className="nav-number">{item.number}</span>
        <span className="nav-glyph" aria-hidden="true">{item.glyph}</span>
        <span>{mobile && item.label === "New investigation" ? "New" : item.label}</span>
        {active && <span className="nav-active-mark" />}
      </Link>
    );
  });

  return (
    <>
      <aside className="desktop-sidebar tf-sidebar">
        <Link href="/" className="brand-link tf-brand">
          <span className="brand-mark">TF</span>
          <span className="tf-brand-name">ThreatForge <small>AI SECURITY PLATFORM</small></span>
        </Link>
        <div className="tf-sidebar-rule" />
        <p className="sidebar-caption">INVESTIGATION CONSOLE</p>
        <nav className="mt-5 space-y-1" aria-label="Primary navigation">
          {navLinks()}
        </nav>
        <div className="tf-sidebar-bottom">
          <div className="tf-sidebar-status"><span className="tf-live-pulse" /> LOCAL ENVIRONMENT</div>
          <div className="flex items-center gap-3 px-2 py-3">
            <div className="tf-analyst-avatar">A</div>
            <div className="min-w-0">
              <p className="truncate text-xs font-semibold">Analyst Workspace</p>
              <p className="text-[11px] text-forge-muted">Private session</p>
            </div>
          </div>
          <p className="tf-sidebar-version">THREATFORGE / BUILD 01</p>
        </div>
      </aside>
      <div className="mobile-navigation tf-mobile-nav">
        <Link href="/" className="brand-link tf-brand">
          <span className="brand-mark">TF</span><span className="tf-brand-name">ThreatForge <small>AI SECURITY</small></span>
        </Link>
        <nav className="mobile-navigation-links" aria-label="Primary navigation">{navLinks(true)}</nav>
      </div>
    </>
  );
}
