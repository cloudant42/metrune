import { cookies } from "next/headers";
import { cache } from "react";
import { isSessionToken } from "@/lib/session";

export type Overview = {
  totalTokens: number;
  totalCost: number;
  sessions: number;
  activeUsers: number;
};

export type TimeseriesPoint = { bucket: string; tokens: number; cost: number; sessions: number };
export type Breakdown = { dimension: string; tokens: number; cost: number; sessions: number };
export type CategoryModelBreakdown = { category: string; model: string; tokens: number; cost: number; sessions: number };
export type WorkflowModelBreakdown = { signal: string; model: string; count: number; tokens: number; cost: number; sessions: number };
export type ClassificationOverhead = {
  provider: string;
  model: string;
  measurement: "reported" | "estimated" | "unavailable";
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  reasoningTokens: number;
  requests: number;
};
export type TokenBreakdown = { input: number; output: number; cacheRead: number; cacheWrite: number; reasoning: number };
export type Cost = { amount: number; currency: string; kind: string };
export type CategoryAssignment = {
  categoryId: string;
  confidence: number;
  taxonomyVersion: string;
  classifierId: string;
  classificationStatus: string;
};
export type SessionDetail = {
  schemaVersion: string;
  sessionKey: string;
  clientId: string;
  projectAlias?: string | null;
  category: CategoryAssignment;
  classifierUsage: {
    providerId: string;
    modelId: string;
    tokens: TokenBreakdown;
    cost: Cost;
    requestCount: number;
    measurement: string;
  };
  signalCapabilities: { signal: string; supported: boolean }[];
  turnDetailTruncated: boolean;
  turns: {
    sequence: number;
    category: CategoryAssignment;
    classificationMethod: "rule" | "semantic_model" | "inherited" | "none";
    classificationCached: boolean;
    workflowSignals: { signal: string; count: number; modelStepIndex?: number }[];
    modelActivity: {
      sequence: number;
      providerId: string;
      modelId: string;
      tokens: TokenBreakdown;
      cost: Cost;
      callCount: number;
    }[];
  }[];
};
export type Session = {
  sessionKey: string;
  installationId: string;
  clientId: string;
  projectAlias: string;
  categoryId: string;
  categoryConfidence: number;
  classificationStatus: string;
  totalTokens: number;
  totalCost: number;
  endedAtMs: number;
};

export type Facets = { teams: string[]; projects: string[]; categories: string[]; clients: string[]; statuses: string[] };
export type Team = { id: string; name: string; installations: number; createdAt: string };
export type Installation = {
  id: string;
  name: string;
  teamId: string | null;
  teamName: string | null;
  createdAt: string;
  lastSeenAt: string | null;
  lastClientVersion: string | null;
  revoked: boolean;
};
export type OrgSettings = {
  organizationName: string;
  retentionDays: number;
  ssoEnforced: boolean;
  localLoginEnabled: boolean;
  mailerConfigured: boolean;
};
export type ClassifierSettings = {
  enabled: boolean;
  executionMode: "local" | "managed";
  providerId: string;
  protocol: string;
  endpoint: string;
  model: string;
  credentialId: string;
  configVersion: string;
  credentialAvailable: boolean;
  responseMode: "auto" | "structured" | "prompt_json";
};
export type ProviderCredential = {
  credentialId: string;
  providerId: string;
  version: number;
  createdAt: string;
  clientsOnVersion: number;
};
export type OrganizationMembership = {
  id: string;
  name: string;
  role: "viewer" | "analyst" | "admin";
};
export type CurrentUser = {
  id: string;
  organizationId: string | null;
  organizationName: string | null;
  email: string;
  displayName: string | null;
  role: "viewer" | "analyst" | "admin" | null;
  organizations: OrganizationMembership[];
};
export type Member = {
  userId: string;
  email: string;
  displayName: string | null;
  role: "viewer" | "analyst" | "admin";
  createdAt: string;
};
export type Invitation = {
  id: string;
  email: string;
  role: "viewer" | "analyst" | "admin";
  status: "manual" | "pending" | "delivery_failed" | "expired" | "accepted" | "revoked";
  createdAt: string;
  expiresAt: string;
};
export type MyInstallation = {
  id: string;
  name: string;
  platform: string;
  teamName: string | null;
  createdAt: string;
  lastSeenAt: string | null;
  lastClientVersion: string | null;
  revoked: boolean;
};
export type MyUsage = {
  overview: Overview;
  providers: Breakdown[];
  models: Breakdown[];
  clients: Breakdown[];
  categories: Breakdown[];
  timeseries: TimeseriesPoint[];
};
export type Price = {
  id: string;
  scope: "default" | "organization";
  providerId: string;
  modelId: string;
  currency: string;
  price: {
    inputPerMillion: number;
    outputPerMillion: number;
    cacheReadPerMillion: number;
    cacheWritePerMillion: number;
    reasoningPerMillion: number;
    requestPerRequest: number;
    imagePerImage: number;
  };
  authority: string;
  catalogVersion: string;
  effectiveFrom: string;
  updatedAt: string;
};

const base = () => process.env.METRUNE_API_URL ?? "http://localhost:8080";

/**
 * The signed-in browser session is the only credential the dashboard ever
 * forwards. There is deliberately no fallback: a shared service token is not
 * tied to a user, so any fallback would serve organization data — and accept
 * mutations — for anonymous visitors. `isSessionToken` additionally refuses a
 * cookie holding a service token, which the API would otherwise honour.
 */
async function token() {
  const store = await cookies();
  const session = store.get("metrune_session")?.value;
  return isSessionToken(session) ? session : undefined;
}

async function api<T>(path: string, query = ""): Promise<T> {
  const auth = await token();
  if (!auth) throw new Error(`${path} returned 401 without a browser session`);
  const response = await fetch(`${base()}${path}${query ? `?${query}` : ""}`, {
    headers: { Authorization: `Bearer ${auth}` },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json() as Promise<T>;
}

export async function adminMutation(
  path: string,
  method: "POST" | "PATCH" | "DELETE",
  body?: unknown,
): Promise<{ ok: boolean; status: number; data?: unknown; error?: string }> {
  const auth = await token();
  if (!auth) return { ok: false, status: 401, error: "not signed in" };
  try {
    const response = await fetch(`${base()}${path}`, {
      method,
      headers: { Authorization: `Bearer ${auth}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    });
    if (response.status === 204) return { ok: true, status: 204 };
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) return { ok: false, status: response.status, error: payload.error ?? `HTTP ${response.status}` };
    return { ok: true, status: response.status, data: payload };
  } catch (error) {
    return { ok: false, status: 502, error: error instanceof Error ? error.message : "request failed" };
  }
}

export async function adminJsonMutation<T>(
  path: string,
  body: unknown,
): Promise<{ ok: boolean; status: number; data?: T; error?: string }> {
  const auth = await token();
  if (!auth) return { ok: false, status: 401, error: "not signed in" };
  try {
    const response = await fetch(`${base()}${path}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${auth}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) return { ok: false, status: response.status, error: payload.error ?? `HTTP ${response.status}` };
    return { ok: true, status: response.status, data: payload as T };
  } catch (error) {
    return { ok: false, status: 502, error: error instanceof Error ? error.message : "request failed" };
  }
}

/* Deduplicated per request: the root layout and the page guards both need the
   signed-in identity, and they should share one /v1/auth/me round-trip. */
export const getCurrentUser = cache(async (): Promise<CurrentUser | null> => {
  try {
    return await api<CurrentUser>("/v1/auth/me");
  } catch {
    return null;
  }
});

export async function getProfileData(installationId?: string): Promise<{
  user: CurrentUser;
  usage: MyUsage;
  installations: MyInstallation[];
} | null> {
  const user = await getCurrentUser();
  if (!user) return null;
  try {
    const installations = await api<MyInstallation[]>("/v1/me/installations");
    const ownedInstallation = installationId
      ? installations.some(item => item.id === installationId)
      : false;
    const usageQuery = ownedInstallation
      ? new URLSearchParams({ installationId: installationId as string }).toString()
      : "";
    const usage = await api<MyUsage>("/v1/me/usage", usageQuery);
    return { user, usage, installations };
  } catch {
    return null;
  }
}

export async function getTeams(): Promise<Team[]> {
  try {
    return await api<Team[]>("/v1/org/teams");
  } catch {
    return [];
  }
}

export async function getMyInstallations(): Promise<MyInstallation[]> {
  try {
    return await api<MyInstallation[]>("/v1/me/installations");
  } catch {
    return [];
  }
}

export async function getMyUsage(): Promise<MyUsage | null> {
  try {
    return await api<MyUsage>("/v1/me/usage");
  } catch {
    return null;
  }
}

export async function getPrices(): Promise<Price[]> {
  try {
    return await api<Price[]>("/v1/org/prices");
  } catch {
    return [];
  }
}

export type PageParams = Record<string, string | undefined>;

export function resolveQuery(params: PageParams): URLSearchParams {
  const query = new URLSearchParams();
  for (const key of ["team", "project", "category", "client", "status", "workflow"]) {
    if (params[key]) query.set(key, params[key] as string);
  }
  const days = Number.parseInt(params.range ?? "30", 10);
  const rangeDays = Number.isFinite(days) ? Math.min(365, Math.max(1, days)) : 30;
  const to = new Date();
  const from = new Date(to);
  from.setUTCDate(from.getUTCDate() - rangeDays + 1);
  query.set("from", from.toISOString().slice(0, 10));
  query.set("to", to.toISOString().slice(0, 10));
  return query;
}

/* Dashboard reads fail closed: a failed request yields null so the page can
   say so, and never plausible-looking organization data. The error is logged
   because the rendered "unavailable" panel is otherwise indistinguishable from
   a transient upstream failure, leaving nothing to diagnose. */
async function live<T>(load: () => Promise<T>): Promise<T | null> {
  try {
    return await load();
  } catch (error) {
    console.error("dashboard read failed:", error instanceof Error ? error.message : error);
    return null;
  }
}

export type OverviewData = {
  overview: Overview;
  timeseries: TimeseriesPoint[];
  categories: Breakdown[];
  models: Breakdown[];
  clients: Breakdown[];
};

export async function getOverviewData(params: PageParams): Promise<OverviewData | null> {
  const query = resolveQuery(params).toString();
  return live(async () => {
    const [overview, timeseries, categories, models, clients] = await Promise.all([
      api<Overview>("/v1/analytics/overview", query),
      api<TimeseriesPoint[]>("/v1/analytics/timeseries", query),
      api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=category`),
      api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=model`),
      api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=client`),
    ]);
    return { overview, timeseries, categories, models, clients };
  });
}

export async function getUsageBreakdown(params: PageParams, dimension: string): Promise<Breakdown[] | null> {
  const query = resolveQuery(params).toString();
  return live(() => api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=${dimension}`));
}

export type SessionsResult =
  | { kind: "live"; sessions: Session[]; hasMore: boolean; page: number }
  | { kind: "forbidden" }
  | { kind: "unauthorized" }
  | { kind: "unavailable" };

async function fetchSessions(path: string, query: URLSearchParams, page: number, pageSize: number): Promise<SessionsResult> {
  query.set("limit", String(pageSize + 1));
  query.set("offset", String(page * pageSize));
  try {
    const rows = await api<Session[]>(path, query.toString());
    return { kind: "live", sessions: rows.slice(0, pageSize), hasMore: rows.length > pageSize, page };
  } catch (error) {
    if (error instanceof Error && /\b401\b/.test(error.message)) return { kind: "unauthorized" };
    if (error instanceof Error && /\b403\b/.test(error.message)) return { kind: "forbidden" };
    return { kind: "unavailable" };
  }
}

export async function getOrgSessions(params: PageParams, page: number, sort: string, pageSize = 50): Promise<SessionsResult> {
  const query = resolveQuery(params);
  query.set("sort", sort);
  return fetchSessions("/v1/analytics/sessions", query, page, pageSize);
}

export async function getMySessions(params: PageParams, page: number, sort: string, pageSize = 50): Promise<SessionsResult> {
  const query = resolveQuery(params);
  query.set("sort", sort);
  if (params.installation) query.set("installationId", params.installation);
  return fetchSessions("/v1/me/sessions", query, page, pageSize);
}

export type ModelsData = {
  categoryModels: CategoryModelBreakdown[];
  workflowModels: WorkflowModelBreakdown[];
  classificationOverhead: ClassificationOverhead[];
  providers: Breakdown[];
};

export async function getModelsData(params: PageParams): Promise<ModelsData | null> {
  const query = resolveQuery(params).toString();
  return live(async () => {
    const [categoryModels, workflowModels, classificationOverhead, providers] = await Promise.all([
      api<CategoryModelBreakdown[]>("/v1/analytics/category-model", query),
      api<WorkflowModelBreakdown[]>("/v1/analytics/workflow-model", query),
      api<ClassificationOverhead[]>("/v1/analytics/classification-overhead", query),
      api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=provider`),
    ]);
    return { categoryModels, workflowModels, classificationOverhead, providers };
  });
}

export async function getSessionDetail(sessionKey: string): Promise<SessionDetail | null> {
  try {
    return await api<SessionDetail>(`/v1/analytics/sessions/${encodeURIComponent(sessionKey)}`);
  } catch {
    return null;
  }
}

export async function getFacets(params: PageParams): Promise<Facets | null> {
  const query = resolveQuery({ range: params.range }).toString();
  return live(() => api<Facets>("/v1/analytics/facets", query));
}

export type AdminData = {
  members: Member[];
  invitations: Invitation[];
  teams: Team[];
  installations: Installation[];
  settings: OrgSettings;
  classifier: ClassifierSettings;
  credentials: ProviderCredential[];
};

export async function getAdminData(): Promise<AdminData | null> {
  return live(async () => {
    const [members, invitations, teams, installations, settings, classifier, credentials] = await Promise.all([
      api<Member[]>("/v1/org/members"),
      api<Invitation[]>("/v1/org/invitations"),
      api<Team[]>("/v1/org/teams"),
      api<Installation[]>("/v1/org/installations"),
      api<OrgSettings>("/v1/org/settings"),
      api<ClassifierSettings>("/v1/org/classifier"),
      api<ProviderCredential[]>("/v1/org/credentials"),
    ]);
    return { members, invitations, teams, installations, settings, classifier, credentials };
  });
}

export async function getOrgSettings(): Promise<OrgSettings | null> {
  try {
    return await api<OrgSettings>("/v1/org/settings");
  } catch {
    return null;
  }
}
