import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";

const navigation = [
  { label: "New investigation", href: "/", glyph: "＋" },
  { label: "Workspace", href: "/workspace", glyph: "⌁" },
  { label: "Casebook", href: "/history", glyph: "▤" },
  { label: "Report", href: "/report", glyph: "▧" },
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
        <span className="nav-glyph" aria-hidden="true">{item.glyph}</span>
        <span>{mobile && item.label === "New investigation" ? "New" : item.label}</span>
      </Link>
    );
  });

  return (
    <>
      <aside className="desktop-sidebar">
        <Link href="/" className="brand-link">
          <span className="brand-mark">TF</span>
          <span>ThreatForge</span>
        </Link>
        <p className="sidebar-caption">Investigation console</p>
        <nav className="mt-5 space-y-1" aria-label="Primary navigation">
          {navLinks()}
        </nav>
        <div className="mt-auto border-t border-forge-border pt-3">
          <div className="flex items-center gap-2 px-2 py-2">
            <div className="grid h-7 w-7 place-items-center rounded-full bg-forge-raised text-xs">A</div>
            <div className="min-w-0">
              <p className="truncate text-xs font-medium">Analyst Workspace</p>
              <p className="text-[11px] text-forge-muted">Local session</p>
            </div>
          </div>
        </div>
      </aside>
      <div className="mobile-navigation">
        <Link href="/" className="brand-link">
          <span className="brand-mark">TF</span>
          <span>ThreatForge</span>
        </Link>
        <nav className="mobile-navigation-links" aria-label="Primary navigation">
          {navLinks(true)}
        </nav>
      </div>
    </>
  );
}
