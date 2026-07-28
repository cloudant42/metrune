import { redirect } from "next/navigation";
import { LogoutButton } from "@/components/auth";
import { BreakdownBars, TrendChart } from "@/components/charts";
import { ClientEnrollment, UsageFilter } from "@/components/profile";
import { getProfileData } from "@/lib/api";
import { formatCompact, formatMoney, shortModel } from "@/lib/format";

export const dynamic = "force-dynamic";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function ProfilePage({ searchParams }: PageProps) {
  const rawParams = await searchParams;
  const requestedInstallation = typeof rawParams.installation === "string"
    ? rawParams.installation
    : undefined;
  const data = await getProfileData(requestedInstallation);
  if (!data) redirect("/login");
  const { user, usage, installations, teams } = data;
  const selectedInstallation = requestedInstallation
    ? installations.find(item => item.id === requestedInstallation)
    : undefined;
  if (requestedInstallation && !selectedInstallation) redirect("/profile");
  const name = user.displayName ?? user.email;
  const serverUrl = process.env.METRUNE_PUBLIC_API_URL ?? "http://localhost:8080";
  const releaseBaseUrl = process.env.METRUNE_CLIENT_RELEASE_BASE_URL ?? `${serverUrl}/v1/downloads`;
  const hasUsage = usage.overview.sessions > 0;
  const hasInstallations = installations.length > 0;
  return (
    <>
      <section className="profile-heading">
        <div className="profile-identity"><span className="avatar large">{name.slice(0, 2).toUpperCase()}</span><div><h2>{name}</h2><p>{user.email} · {user.role}</p></div></div>
        <LogoutButton />
      </section>
      <UsageFilter installations={installations} selected={selectedInstallation?.id} />
      {hasUsage ? (
        <>
          <section className="metric-grid" aria-label="My usage summary">
            <Metric label="My spend" value={formatMoney(usage.overview.totalCost)} detail={selectedInstallation ? selectedInstallation.name : "Last 30 days"} />
            <Metric label="My tokens" value={formatCompact(usage.overview.totalTokens)} detail={selectedInstallation ? "This client" : "Across owned clients"} />
            <Metric label="My sessions" value={formatCompact(usage.overview.sessions)} detail="Private to your profile" />
            <Metric label="My clients" value={String(installations.filter(item => !item.revoked).length)} detail="Active installations" />
          </section>
          <section className="panel" aria-labelledby="personal-trend">
            <div className="panel-header"><div><p className="eyebrow">Your own cost over the last 30 days</p><h2 id="personal-trend">My usage trend</h2></div></div>
            {usage.timeseries.length ? <TrendChart points={usage.timeseries} /> : <p className="empty">No usage in this range yet.</p>}
          </section>
          <div className="three-column">
            <section className="panel"><div className="panel-header"><h2>Providers</h2></div><BreakdownBars values={usage.providers} /></section>
            <section className="panel"><div className="panel-header"><h2>Models</h2></div><BreakdownBars values={usage.models} format={shortModel} /></section>
            <section className="panel"><div className="panel-header"><h2>Coding agents</h2></div><BreakdownBars values={usage.clients} /></section>
          </div>
        </>
      ) : (
        <section className="panel onboarding" aria-labelledby="onboarding-title">
          <div className="panel-body">
            {hasInstallations ? (
              <>
                <p className="eyebrow">No usage in the last 30 days</p>
                <h2 id="onboarding-title">{selectedInstallation ? `No recent usage from ${selectedInstallation.name}` : "No recent personal usage"}</h2>
                <p className="onboarding-copy">This client is still available in your history and filters. New usage will appear after its next upload.</p>
              </>
            ) : (
              <>
                <p className="eyebrow">Getting started</p>
                <h2 id="onboarding-title">Connect your first client</h2>
                <p className="onboarding-copy">Your private analytics appear here as soon as an enrolled client uploads usage. Create a one-time enrollment code below — it takes about a minute.</p>
                <ol className="onboarding-steps">
                  <li>Create an enrollment code</li>
                  <li>Install the client on your machine</li>
                  <li>Run the enroll command, then code with your AI tools as usual</li>
                </ol>
              </>
            )}
          </div>
        </section>
      )}
      <div className="profile-client-grid">
        <ClientEnrollment installations={installations} teams={teams} serverUrl={serverUrl} releaseBaseUrl={releaseBaseUrl} />
      </div>
    </>
  );
}

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <article className="metric"><p>{label}</p><strong>{value}</strong><span>{detail}</span></article>;
}
