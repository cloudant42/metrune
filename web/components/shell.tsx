"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  CategoryIcon,
  ChevronIcon,
  LogoutIcon,
  MarkIcon,
  OverviewIcon,
  SettingsIcon,
  TableIcon,
  TeamIcon,
  UsageIcon,
  UserIcon,
} from "./icons";
import { ThemeSwitch } from "./theme";
import type { OrganizationMembership } from "@/lib/api";

const titles: Record<string, { title: string; description: string }> = {
  "/": { title: "Overview", description: "Cost, tokens and activity across your organization" },
  "/usage": { title: "Usage explorer", description: "Break spend down by any dimension" },
  "/sessions": { title: "Sessions", description: "Permission-controlled session drilldown" },
  "/models": { title: "Models", description: "Which models power which kind of work" },
  "/profile": { title: "My profile", description: "Your private usage and enrolled clients" },
  "/admin": { title: "Administration", description: "Teams, retention, identity and classification" },
  "/admin/pricing": { title: "Pricing", description: "Provider and model rates used for cost" },
};

function NavItem({ href, label, icon }: { href: string; label: string; icon: ReactNode }) {
  const pathname = usePathname();
  const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
  return (
    <Link href={href} className={`nav-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined} title={label}>
      {icon}<span>{label}</span>
    </Link>
  );
}

function AccountMenu({
  name,
  email,
  canAdmin,
  signedIn,
  organizationId,
  organizations,
}: {
  name: string;
  email: string;
  canAdmin: boolean;
  signedIn: boolean;
  organizationId?: string | null;
  organizations: OrganizationMembership[];
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [switching, setSwitching] = useState<string | null>(null);
  const [switchError, setSwitchError] = useState<string | null>(null);
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent) {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    setOpen(false);
    router.replace("/login");
    router.refresh();
  }

  async function switchWorkspace(nextOrganizationId: string) {
    if (nextOrganizationId === organizationId) {
      setOpen(false);
      return;
    }
    setSwitching(nextOrganizationId);
    setSwitchError(null);
    const response = await fetch("/api/auth/organization", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ organizationId: nextOrganizationId }),
    });
    const payload = await response.json().catch(() => ({}));
    setSwitching(null);
    if (!response.ok) {
      setSwitchError(payload.error ?? "Could not switch workspace.");
      return;
    }
    setOpen(false);
    router.replace("/");
    router.refresh();
  }

  return (
    <div className="account" ref={container}>
      <button type="button" className="account-button" aria-expanded={open} aria-haspopup="menu" onClick={() => setOpen(value => !value)} title={name}>
        <span className="avatar" aria-hidden="true">{name.slice(0, 2).toUpperCase()}</span>
        <span className="account-name"><strong>{name}</strong><small>{email}</small></span>
        <span className="chevron" aria-hidden="true"><ChevronIcon /></span>
      </button>
      {open && (
        <div className="menu" role="menu">
          {signedIn && (
            <>
              <p className="menu-title">Workspace</p>
              {organizations.map(organization => (
                <button
                  className={`menu-item workspace-menu-item${organization.id === organizationId ? " active" : ""}`}
                  type="button"
                  role="menuitemradio"
                  aria-checked={organization.id === organizationId}
                  disabled={switching !== null}
                  key={organization.id}
                  onClick={() => switchWorkspace(organization.id)}
                >
                  <span className="menu-workspace-mark" aria-hidden="true">{organization.id === organizationId ? "✓" : ""}</span>
                  <span><strong>{organization.name}</strong><small>{organization.role}</small></span>
                </button>
              ))}
              <Link className="menu-item" role="menuitem" href="/organizations" onClick={() => setOpen(false)}>
                <span className="menu-workspace-mark" aria-hidden="true">+</span>
                <span>All workspaces</span>
              </Link>
              {switchError && <p className="menu-error" role="alert">{switchError}</p>}
              <div className="menu-separator" />
            </>
          )}
          <Link className="menu-item" role="menuitem" href="/profile" onClick={() => setOpen(false)}><UserIcon size={16} />My profile</Link>
          {canAdmin && <Link className="menu-item" role="menuitem" href="/admin" onClick={() => setOpen(false)}><SettingsIcon size={16} />Settings</Link>}
          <div className="menu-separator" />
          <p className="menu-title">Appearance</p>
          <ThemeSwitch />
          <div className="menu-separator" />
          {signedIn
            ? <button type="button" className="menu-item" role="menuitem" onClick={signOut}><LogoutIcon />Sign out</button>
            : <Link className="menu-item" role="menuitem" href="/login" onClick={() => setOpen(false)}><LogoutIcon />Sign in</Link>}
        </div>
      )}
    </div>
  );
}

export function Shell({
  children,
  orgName,
  role,
  userName,
  userEmail,
  organizationId,
  organizations,
}: {
  children: ReactNode;
  orgName: string;
  role?: string | null;
  userName?: string;
  userEmail?: string;
  organizationId?: string | null;
  organizations?: OrganizationMembership[];
}) {
  const pathname = usePathname();
  const router = useRouter();
  const authFlow = pathname.startsWith("/login")
    || pathname.startsWith("/organizations")
    || pathname.startsWith("/accept-invite")
    || pathname.startsWith("/forgot-password")
    || pathname.startsWith("/reset-password")
    || pathname.startsWith("/device");
  const selectionRequired = Boolean(userName) && !organizationId
    && !authFlow;
  useEffect(() => {
    if (selectionRequired) router.replace("/organizations");
  }, [router, selectionRequired]);
  if (authFlow) return <>{children}</>;
  if (selectionRequired) return <div className="loading-shell"><div className="loading-heading" /></div>;
  const heading = titles[pathname]
    ?? Object.entries(titles)
      .filter(([href]) => href !== "/" && pathname.startsWith(`${href}/`))
      .sort(([left], [right]) => right.length - left.length)[0]?.[1]
    ?? titles["/"];
  // An absent role means there is no verified active membership. Treat it as
  // least privilege even in development; the API remains the final guard.
  const canDrillDown = role === "admin" || role === "analyst";
  const canAdmin = role === "admin";
  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <aside className="sidebar">
        <Link className="brand" href="/" aria-label="Metrune overview">
          <span className="brand-mark"><MarkIcon size={26} /></span>
          <span className="brand-name">
            <strong>Metrune</strong>
            {orgName !== "Metrune" && <small>{orgName}</small>}
          </span>
        </Link>
        <nav aria-label="Primary navigation">
          <p className="nav-label">Analyze</p>
          <NavItem href="/" label="Overview" icon={<OverviewIcon />} />
          <NavItem href="/usage" label="Usage" icon={<UsageIcon />} />
          <NavItem href="/models" label="Models" icon={<CategoryIcon />} />
          {canDrillDown && <NavItem href="/sessions" label="Sessions" icon={<TableIcon />} />}
          {canAdmin && (
            <>
              <p className="nav-label nav-section">Manage</p>
              <NavItem href="/admin" label="Administration" icon={<TeamIcon />} />
            </>
          )}
        </nav>
        <div className="sidebar-footer">
          <AccountMenu
            name={userName ?? orgName}
            email={userName ? userEmail ?? "" : "Not signed in"}
            canAdmin={canAdmin}
            signedIn={Boolean(userName)}
            organizationId={organizationId}
            organizations={organizations ?? []}
          />
        </div>
      </aside>
      <main id="main-content" className="main" tabIndex={-1}>
        <div className="content">
          <header className="page-header">
            <p>{heading.description}</p>
            <h1>{heading.title}</h1>
          </header>
          {children}
        </div>
      </main>
    </div>
  );
}
