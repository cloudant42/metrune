"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState, type FormEvent } from "react";
import type { Price } from "@/lib/api";

type Draft = {
  id?: string;
  providerId: string;
  modelId: string;
  currency: string;
  inputPerMillion: string;
  outputPerMillion: string;
  cacheReadPerMillion: string;
  cacheWritePerMillion: string;
  reasoningPerMillion: string;
  authority: string;
};

const empty: Draft = {
  providerId: "", modelId: "", currency: "USD",
  inputPerMillion: "0", outputPerMillion: "0", cacheReadPerMillion: "0",
  cacheWritePerMillion: "0", reasoningPerMillion: "0",
  authority: "organization_override",
};

const pageSize = 50;

export function PricingManager({ prices }: { prices: Price[] }) {
  const router = useRouter();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const overrides = useMemo(() => prices.filter(item => item.scope === "organization"), [prices]);
  const catalog = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const base = prices.filter(item => item.scope !== "organization");
    return needle ? base.filter(item => `${item.providerId}/${item.modelId}`.toLowerCase().includes(needle)) : base;
  }, [prices, query]);
  const pageCount = Math.max(1, Math.ceil(catalog.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const visible = catalog.slice(currentPage * pageSize, (currentPage + 1) * pageSize);

  function edit(item: Price | null) {
    setMessage(null);
    setError(null);
    if (item === null) {
      setDraft(empty);
    } else {
      setDraft({
        id: item.scope === "organization" ? item.id : undefined,
        providerId: item.providerId,
        modelId: item.modelId,
        currency: item.currency,
        inputPerMillion: String(item.price.inputPerMillion),
        outputPerMillion: String(item.price.outputPerMillion),
        cacheReadPerMillion: String(item.price.cacheReadPerMillion),
        cacheWritePerMillion: String(item.price.cacheWritePerMillion),
        reasoningPerMillion: String(item.price.reasoningPerMillion),
        authority: item.scope === "organization" ? item.authority : "organization_override",
      });
    }
    requestAnimationFrame(() => document.getElementById("price-editor")?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!draft) return;
    setBusy(true); setError(null); setMessage(null);
    const body = {
      providerId: draft.providerId, modelId: draft.modelId, currency: draft.currency,
      inputPerMillion: Number(draft.inputPerMillion), outputPerMillion: Number(draft.outputPerMillion),
      cacheReadPerMillion: Number(draft.cacheReadPerMillion), cacheWritePerMillion: Number(draft.cacheWritePerMillion),
      reasoningPerMillion: Number(draft.reasoningPerMillion), requestPerRequest: 0, imagePerImage: 0,
      authority: draft.authority,
    };
    const response = await fetch(draft.id ? `/api/prices/${draft.id}` : "/api/prices", {
      method: draft.id ? "PATCH" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    setBusy(false);
    if (!response.ok) setError(payload.error ?? "Could not save the price.");
    else {
      setMessage("Price saved. New ingests will use this version.");
      setDraft(null);
      router.refresh();
    }
  }

  async function remove(item: Price) {
    if (!window.confirm(`Remove the organization override for ${item.providerId}/${item.modelId}?`)) return;
    setMessage(null);
    const response = await fetch(`/api/prices/${item.id}`, { method: "DELETE" });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      setError(payload.error ?? "Could not remove the price.");
    } else router.refresh();
  }

  return (
    <>
      {draft && (
        <section className="panel editor-panel" id="price-editor" aria-labelledby="price-editor-title">
          <div className="panel-header">
            <div><p className="eyebrow">Shared organization rule</p><h2 id="price-editor-title">{draft.id ? "Edit price" : draft.providerId ? `Override ${draft.providerId}/${draft.modelId}` : "Create provider/model price"}</h2></div>
            <button className="btn ghost small" type="button" onClick={() => setDraft(null)}>Cancel</button>
          </div>
          <form className="price-form panel-body" onSubmit={save}>
            <label className="field"><span>Provider ID</span><input required value={draft.providerId} onChange={event => setDraft({ ...draft, providerId: event.target.value })} placeholder="openai" /></label>
            <label className="field wide"><span>Model ID</span><input required value={draft.modelId} onChange={event => setDraft({ ...draft, modelId: event.target.value })} placeholder="gpt-5" /></label>
            <label className="field"><span>Currency</span><input required maxLength={3} value={draft.currency} onChange={event => setDraft({ ...draft, currency: event.target.value.toUpperCase() })} /></label>
            <Rate label="Input / 1M" value={draft.inputPerMillion} onChange={value => setDraft({ ...draft, inputPerMillion: value })} />
            <Rate label="Output / 1M" value={draft.outputPerMillion} onChange={value => setDraft({ ...draft, outputPerMillion: value })} />
            <Rate label="Cache read / 1M" value={draft.cacheReadPerMillion} onChange={value => setDraft({ ...draft, cacheReadPerMillion: value })} />
            <Rate label="Cache write / 1M" value={draft.cacheWritePerMillion} onChange={value => setDraft({ ...draft, cacheWritePerMillion: value })} />
            <Rate label="Reasoning / 1M" value={draft.reasoningPerMillion} onChange={value => setDraft({ ...draft, reasoningPerMillion: value })} />
            <label className="field"><span>Authority</span><select value={draft.authority} onChange={event => setDraft({ ...draft, authority: event.target.value })}>
              <option value="organization_override">Organization override</option>
              <option value="official_provider">Official provider</option>
              <option value="self_hosted">Self-hosted</option>
              <option value="manual">Manual</option>
            </select></label>
            <button className="btn price-save" type="submit" disabled={busy}>{busy ? "Saving…" : "Save price"}</button>
          </form>
          {error && <p className="form-error" role="alert">{error}</p>}
          <p className="panel-note">All signed-in members can manage shared pricing in this release. Every change is versioned and audited. Historical totals are not silently repriced.</p>
        </section>
      )}
      {error && !draft && <p className="form-error" role="alert">{error}</p>}
      {message && <p className="form-ok panel-flash" role="status">{message}</p>}

      <section className="panel" aria-labelledby="overrides-title">
        <div className="panel-header">
          <div><p className="eyebrow">Your rules</p><h2 id="overrides-title">Organization overrides</h2></div>
          {!draft && <button className="btn ghost small" type="button" onClick={() => edit(null)}>Add price</button>}
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Provider / model</th><th className="num">Input / 1M</th><th className="num">Output / 1M</th><th className="num">Cache read</th><th>Authority</th><th className="actions-col">Actions</th></tr></thead>
            <tbody>
              {overrides.map(item => (
                <tr key={item.id}>
                  <td><strong>{item.providerId}</strong> <code>{item.modelId}</code></td>
                  <td className="num">{item.currency} {item.price.inputPerMillion.toFixed(4)}</td>
                  <td className="num">{item.currency} {item.price.outputPerMillion.toFixed(4)}</td>
                  <td className="num">{item.currency} {item.price.cacheReadPerMillion.toFixed(4)}</td>
                  <td>{item.authority}</td>
                  <td className="actions-col">
                    <button className="btn ghost small" type="button" onClick={() => edit(item)}>Edit</button>
                    <button className="btn danger small" type="button" onClick={() => remove(item)}>Remove</button>
                  </td>
                </tr>
              ))}
              {overrides.length === 0 && <tr><td colSpan={6} className="empty">No organization overrides. Default catalog prices apply to all usage.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel" aria-labelledby="prices-title">
        <div className="panel-header">
          <div><p className="eyebrow">Default catalog</p><h2 id="prices-title">Provider and model prices</h2></div>
          <label className="search-field"><span className="sr-only">Search prices</span><input type="search" value={query} onChange={event => { setQuery(event.target.value); setPage(0); }} placeholder="Search provider or model" /></label>
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Provider / model</th><th className="num">Input / 1M</th><th className="num">Output / 1M</th><th className="num">Cache read</th><th>Source</th><th className="actions-col">Actions</th></tr></thead>
            <tbody>
              {visible.map(item => (
                <tr key={item.id}>
                  <td><strong>{item.providerId}</strong><br /><code>{item.modelId}</code></td>
                  <td className="num">{item.currency} {item.price.inputPerMillion.toFixed(4)}</td>
                  <td className="num">{item.currency} {item.price.outputPerMillion.toFixed(4)}</td>
                  <td className="num">{item.currency} {item.price.cacheReadPerMillion.toFixed(4)}</td>
                  <td><code>{item.catalogVersion}</code></td>
                  <td className="actions-col">
                    <button className="btn ghost small" type="button" onClick={() => edit(item)}>Override</button>
                  </td>
                </tr>
              ))}
              {visible.length === 0 && <tr><td colSpan={6} className="empty">No prices match this search.</td></tr>}
            </tbody>
          </table>
        </div>
        <nav className="pagination" aria-label="Catalog pages">
          <button className="btn ghost small" type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>← Previous</button>
          <span className="page-indicator">Page {currentPage + 1} of {pageCount} · {catalog.length} entries</span>
          <button className="btn ghost small" type="button" disabled={currentPage >= pageCount - 1} onClick={() => setPage(currentPage + 1)}>Next →</button>
        </nav>
      </section>
    </>
  );
}

function Rate({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return <label className="field"><span>{label}</span><input type="number" min="0" step="any" required value={value} onChange={event => onChange(event.target.value)} /></label>;
}
