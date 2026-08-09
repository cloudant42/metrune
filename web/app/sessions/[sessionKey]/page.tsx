import Link from "next/link";
import { getCurrentUser, getSessionDetail } from "@/lib/api";
import { formatCompact, formatMoney, label, shortModel } from "@/lib/format";
import { redirect } from "next/navigation";

type PageProps = { params: Promise<{ sessionKey: string }> };

function tokenTotal(tokens: { input: number; output: number; cacheRead: number; cacheWrite: number; reasoning: number }): number {
  return tokens.input + tokens.output + tokens.cacheRead + tokens.cacheWrite + tokens.reasoning;
}

export default async function SessionDetailPage({ params }: PageProps) {
  const { sessionKey } = await params;
  const user = await getCurrentUser();
  if (!user) redirect(`/login?next=${encodeURIComponent(`/sessions/${sessionKey}`)}`);
  const session = await getSessionDetail(sessionKey);
  if (!session) {
    return (
      <section className="panel" aria-labelledby="session-unavailable-title">
        <div className="panel-header">
          <div><p className="eyebrow">Session unavailable</p><h2 id="session-unavailable-title">This timeline could not be opened</h2></div>
          <Link className="btn ghost" href="/sessions">Back to sessions</Link>
        </div>
        <div className="panel-body"><p>The session may be outside your access scope, no longer retained, or temporarily unavailable.</p></div>
      </section>
    );
  }

  const workTokens = session.turns.reduce((sum, turn) => sum + turn.modelActivity.reduce((stepSum, step) => stepSum + tokenTotal(step.tokens), 0), 0);
  const classifiedTokens = session.turns
    .filter(turn => turn.category.classificationStatus === "classified")
    .reduce((sum, turn) => sum + turn.modelActivity.reduce((stepSum, step) => stepSum + tokenTotal(step.tokens), 0), 0);
  const classifierTokens = tokenTotal(session.classifierUsage.tokens);
  const coverage = workTokens > 0 ? Math.round(classifiedTokens / workTokens * 100) : 0;
  const unsupported = session.signalCapabilities.filter(item => !item.supported).map(item => label(item.signal));

  return (
    <>
      <section className="panel" aria-labelledby="session-detail-title">
        <div className="panel-header">
          <div>
            <p className="muted">{session.projectAlias || "Unassigned project"} · {session.clientId} · No prompts, responses, commands, paths, or exact turn times</p>
            <p className="eyebrow">Metadata-only ordered activity</p>
            <h2 id="session-detail-title">Session {session.sessionKey.slice(0, 8)}</h2>
          </div>
          <Link className="btn ghost" href="/sessions">Back to sessions</Link>
        </div>
        <div className="metric-strip" aria-label="Session semantic coverage and classifier overhead">
          <div><span>Semantic coverage</span><strong>{coverage}%</strong><small>of work tokens</small></div>
          <div><span>Work tokens</span><strong>{formatCompact(workTokens)}</strong><small>coding-agent activity</small></div>
          <div><span>Classifier tokens</span><strong>{formatCompact(classifierTokens)}</strong><small>{session.classifierUsage.measurement || "unavailable"} · separate</small></div>
          <div><span>Classifier requests</span><strong>{session.classifierUsage.requestCount}</strong><small>cache/rule/inherit excluded</small></div>
        </div>
        {unsupported.length > 0 && (
          <div className="coverage-note" role="note">
            Workflow coverage is unavailable for: {unsupported.join(", ")}. Missing support is not counted as zero activity.
          </div>
        )}
        {session.turnDetailTruncated && (
          <div className="coverage-note" role="note">Turn detail exceeded the safe upload size; this session retains legacy aggregate totals only.</div>
        )}
      </section>

      <section className="panel" aria-labelledby="timeline-title">
        <div className="panel-header">
          <div><p className="eyebrow">Turns are ordered; exact timestamps stay local</p><h2 id="timeline-title">Session timeline</h2></div>
        </div>
        <ol className="turn-timeline">
          {session.turns.map(turn => {
            const turnTokens = turn.modelActivity.reduce((sum, step) => sum + tokenTotal(step.tokens), 0);
            const turnCost = turn.modelActivity.reduce((sum, step) => sum + step.cost.amount, 0);
            const method = turn.classificationCached
              ? "Semantic model · cache hit"
              : turn.classificationMethod === "semantic_model"
                ? "Semantic model"
                : label(turn.classificationMethod);
            return (
              <li key={turn.sequence} className="turn-card">
                <div className="turn-heading">
                  <div>
                    <span className="turn-index">Turn {turn.sequence}</span>
                    <strong>{turn.category.classificationStatus === "classified" ? label(turn.category.categoryId) : "Unclassified"}</strong>
                  </div>
                  <div className="turn-meta">
                    <span>{method}</span>
                    <span>{label(turn.category.classificationStatus)}</span>
                    <span>{Math.round(turn.category.confidence * 100)}% confidence</span>
                  </div>
                </div>
                <div className="signal-list" aria-label={`Workflow signals in turn ${turn.sequence}`}>
                  {turn.workflowSignals.map(signal => <span key={`${signal.signal}-${signal.modelStepIndex ?? "none"}`} className="signal-chip">{label(signal.signal)} ×{signal.count}</span>)}
                  {turn.workflowSignals.length === 0 && <span className="muted">No supported workflow signal observed</span>}
                </div>
                <div className="model-transition" aria-label={`Model activity in turn ${turn.sequence}`}>
                  {turn.modelActivity.map((step, index) => (
                    <span key={`${step.sequence}-${step.providerId}-${step.modelId}`}>
                      {index > 0 && <span className="transition-arrow" aria-hidden="true">→</span>}
                      <span className="model-step">
                        <strong>{shortModel(`${step.providerId}/${step.modelId}`)}</strong>
                        <small>{formatCompact(tokenTotal(step.tokens))} tokens · {formatMoney(step.cost.amount)} · {step.callCount} {step.callCount === 1 ? "call" : "calls"}</small>
                      </span>
                    </span>
                  ))}
                </div>
                <div className="turn-total"><span>Turn total</span><strong>{formatCompact(turnTokens)} tokens · {formatMoney(turnCost)}</strong></div>
              </li>
            );
          })}
          {session.turns.length === 0 && <li className="empty">This is a legacy session without turn-level metadata.</li>}
        </ol>
      </section>
    </>
  );
}
