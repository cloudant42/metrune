"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { CategoryIcon, MarkIcon, OverviewIcon, TableIcon, TeamIcon, UsageIcon, UserIcon } from "./icons";

const titles: Record<string, { eyebrow: string; title: string }> = {
  "/": { eyebrow: "AI usage intelligence", title: "Overview" },
  "/usage": { eyebrow: "Breakdown explorer", title: "Usage explorer" },
  "/sessions": { eyebrow: "Permission-controlled drilldown", title: "Sessions" },
  "/models": { eyebrow: "Model mix", title: "Models" },
  "/profile": { eyebrow: "Private personal analytics", title: "My profile" },
  "/admin": { eyebrow: "Organization administration", title: "Admin" },
  "/admin/pricing": { eyebrow: "Cost governance", title: "Provider and model pricing" },
};

function NavItem({ href, label, icon }: { href: string; label: string; icon: ReactNode }) {
  const pathname = usePathname();
  const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
  return (
    <Link href={href} className={`nav-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined}>
      {icon}<span>{label}</span>
    </Link>
  );
}

export function Shell({ children, orgName, live, role }: { children: ReactNode; orgName: string; live: boolean; role?: string }) {
  const pathname = usePathname();
  if (pathname.startsWith("/login")) return <>{children}</>;
  const heading = titles[pathname] ?? titles["/"];
  const canDrillDown = role === "admin" || role === "analyst" || role === undefined;
  const canAdmin = role === "admin" || role === undefined;
  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <aside className="sidebar">
        <Link className="brand" href="/" aria-label="Metrune overview">
          <span className="brand-mark"><MarkIcon /></span><span>Metrune</span>
        </Link>
        <nav aria-label="Primary navigation">
          <p className="nav-label">Analyze</p>
          <NavItem href="/" label="Overview" icon={<OverviewIcon />} />
          <NavItem href="/usage" label="Usage explorer" icon={<UsageIcon />} />
          <NavItem href="/models" label="Models" icon={<CategoryIcon />} />
          {canDrillDown && <NavItem href="/sessions" label="Sessions" icon={<TableIcon />} />}
          <NavItem href="/profile" label="My profile" icon={<UserIcon />} />
          {canAdmin && (
            <>
              <p className="nav-label nav-section">Manage</p>
              <NavItem href="/admin" label="Administration" icon={<TeamIcon />} />
            </>
          )}
        </nav>
        <div className="privacy-note"><span className="status-dot" />Raw prompts stay local</div>
      </aside>
      <main id="main-content" className="main" tabIndex={-1}>
        <header className="topbar">
          <div>
            <p className="eyebrow">{heading.eyebrow}</p>
            <h1>{heading.title}</h1>
          </div>
          <div className="topbar-right">
            <span className={`connection-badge${live ? "" : " offline"}`} title={live ? "Connected to the Metrune API" : "API unreachable — showing demo data"}>
              <span className="status-dot" />{live ? "Live" : "Demo"}
            </span>
            <Link className="org-switcher" href="/profile"><span className="avatar">{orgName.slice(0, 2).toUpperCase()}</span><span><strong>{orgName}</strong><small>Profile & organization</small></span></Link>
          </div>
        </header>
        <div className="content">{children}</div>
      </main>
    </div>
  );
}
