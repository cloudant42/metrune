import { cookies } from "next/headers";

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
  status: "sending" | "pending" | "delivery_failed" | "expired" | "accepted" | "revoked";
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

export type Source = "live" | "demo" | "unavailable";
export type Result<T> = { data: T; source: Source };

const base = () => process.env.METRUNE_API_URL ?? "http://localhost:8080";
async function token() {
  const store = await cookies();
  const session = store.get("metrune_session")?.value;
  if (session) return session;
  // The shared dashboard token is not tied to a signed-in user, so falling back
  // to it would serve organization data to anonymous visitors. It stays a
  // development-only convenience.
  if (process.env.METRUNE_ENV === "production") return undefined;
  return process.env.METRUNE_DASHBOARD_TOKEN;
}

async function api<T>(path: string, query = ""): Promise<T> {
  const auth = await token();
  if (!auth) throw new Error("dashboard token is not configured");
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
): Promise<{ ok: boolean; status: number; error?: string }> {
  const auth = await token();
  if (!auth) return { ok: false, status: 500, error: "dashboard token is not configured" };
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
    return { ok: true, status: response.status };
  } catch (error) {
    return { ok: false, status: 502, error: error instanceof Error ? error.message : "request failed" };
  }
}

export async function adminJsonMutation<T>(
  path: string,
  body: unknown,
): Promise<{ ok: boolean; status: number; data?: T; error?: string }> {
  const auth = await token();
  if (!auth) return { ok: false, status: 500, error: "dashboard token is not configured" };
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

export async function getCurrentUser(): Promise<CurrentUser | null> {
  try {
    return await api<CurrentUser>("/v1/auth/me");
  } catch {
    return null;
  }
}

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

async function demoFallbackAllowed(): Promise<boolean> {
  // Demo fixtures are useful for an explicitly enabled local showcase, but a
  // failed authenticated request must never turn into plausible-looking
  // organization data. Production always fails closed, and a signed-in
  // browser session never receives demo values even when a developer enabled
  // the showcase mode.
  if (process.env.METRUNE_ENV === "production" || process.env.METRUNE_ENABLE_DEMO_DATA !== "1") {
    return false;
  }
  const store = await cookies();
  return !store.get("metrune_session")?.value;
}

async function withFallback<T>(live: () => Promise<T>, demo: T): Promise<Result<T>> {
  try {
    return { data: await live(), source: "live" };
  } catch {
    return (await demoFallbackAllowed())
      ? { data: demo, source: "demo" }
      : { data: demo, source: "unavailable" };
  }
}

export type OverviewData = {
  overview: Overview;
  timeseries: TimeseriesPoint[];
  categories: Breakdown[];
  models: Breakdown[];
  clients: Breakdown[];
};

export async function getOverviewData(params: PageParams): Promise<Result<OverviewData>> {
  const query = resolveQuery(params).toString();
  return withFallback(
    async () => {
      const [overview, timeseries, categories, models, clients] = await Promise.all([
        api<Overview>("/v1/analytics/overview", query),
        api<TimeseriesPoint[]>("/v1/analytics/timeseries", query),
        api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=category`),
        api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=model`),
        api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=client`),
      ]);
      return { overview, timeseries, categories, models, clients };
    },
    demo.overviewData,
  );
}

export async function getUsageBreakdown(params: PageParams, dimension: string): Promise<Result<Breakdown[]>> {
  const query = resolveQuery(params).toString();
  return withFallback(() => api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=${dimension}`), demo.usage);
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

export async function getModelsData(params: PageParams): Promise<Result<ModelsData>> {
  const query = resolveQuery(params).toString();
  return withFallback(
    async () => {
      const [categoryModels, workflowModels, classificationOverhead, providers] = await Promise.all([
        api<CategoryModelBreakdown[]>("/v1/analytics/category-model", query),
        api<WorkflowModelBreakdown[]>("/v1/analytics/workflow-model", query),
        api<ClassificationOverhead[]>("/v1/analytics/classification-overhead", query),
        api<Breakdown[]>("/v1/analytics/breakdowns", `${query}&dimension=provider`),
      ]);
      return { categoryModels, workflowModels, classificationOverhead, providers };
    },
    demo.modelsData,
  );
}

export async function getSessionDetail(sessionKey: string): Promise<SessionDetail | null> {
  try {
    return await api<SessionDetail>(`/v1/analytics/sessions/${encodeURIComponent(sessionKey)}`);
  } catch {
    return null;
  }
}

export async function getFacets(params: PageParams): Promise<Result<Facets>> {
  const query = resolveQuery({ range: params.range }).toString();
  return withFallback(() => api<Facets>("/v1/analytics/facets", query), demo.facets);
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

export async function getAdminData(): Promise<Result<AdminData>> {
  return withFallback(
    async () => {
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
    },
    demo.adminData,
  );
}

export async function getOrgSettings(): Promise<OrgSettings | null> {
  try {
    return await api<OrgSettings>("/v1/org/settings");
  } catch {
    return null;
  }
}

const demo = {
  overviewData: {
    overview: { totalTokens: 14_820_340, totalCost: 812.46, sessions: 684, activeUsers: 31 },
    timeseries: [
      { bucket: "2026-07-16", tokens: 1540120, cost: 83.21, sessions: 71 },
      { bucket: "2026-07-17", tokens: 1832440, cost: 96.74, sessions: 83 },
      { bucket: "2026-07-18", tokens: 1210340, cost: 62.18, sessions: 54 },
      { bucket: "2026-07-19", tokens: 2078140, cost: 111.03, sessions: 92 },
      { bucket: "2026-07-20", tokens: 2389340, cost: 134.12, sessions: 104 },
      { bucket: "2026-07-21", tokens: 2659980, cost: 148.91, sessions: 126 },
      { bucket: "2026-07-22", tokens: 3119980, cost: 176.27, sessions: 154 },
    ] as TimeseriesPoint[],
    categories: [
      { dimension: "implementation", tokens: 5812030, cost: 319.42, sessions: 244 },
      { dimension: "debugging", tokens: 3120120, cost: 175.13, sessions: 152 },
      { dimension: "research", tokens: 2081440, cost: 113.08, sessions: 106 },
      { dimension: "testing", tokens: 1104240, cost: 59.12, sessions: 62 },
    ] as Breakdown[],
    models: [
      { dimension: "anthropic/claude-sonnet-4", tokens: 6831020, cost: 401.37, sessions: 302 },
      { dimension: "openai/gpt-5-codex", tokens: 5087110, cost: 273.28, sessions: 239 },
      { dimension: "google/gemini-2.5-pro", tokens: 2902210, cost: 137.81, sessions: 143 },
    ] as Breakdown[],
    clients: [
      { dimension: "claude", tokens: 6824100, cost: 379.14, sessions: 298 },
      { dimension: "codex", tokens: 4970120, cost: 268.71, sessions: 231 },
      { dimension: "opencode", tokens: 3026120, cost: 164.61, sessions: 155 },
    ] as Breakdown[],
  } as OverviewData,
  usage: [
    { dimension: "implementation", tokens: 5812030, cost: 319.42, sessions: 244 },
    { dimension: "debugging", tokens: 3120120, cost: 175.13, sessions: 152 },
    { dimension: "research", tokens: 2081440, cost: 113.08, sessions: 106 },
    { dimension: "review_refactoring", tokens: 1520880, cost: 84.19, sessions: 71 },
    { dimension: "testing", tokens: 1104240, cost: 59.12, sessions: 62 },
    { dimension: "unknown", tokens: 1181630, cost: 61.52, sessions: 49 },
  ] as Breakdown[],
  sessions: [
    { sessionKey: "9f1a3c87d041f0a2", installationId: "i1", clientId: "codex", projectAlias: "Platform API", categoryId: "implementation", categoryConfidence: 0.94, classificationStatus: "classified", totalTokens: 128420, totalCost: 7.82, endedAtMs: Date.UTC(2026, 6, 22, 14, 31) },
    { sessionKey: "7c2b901ab4e8c1d3", installationId: "i1", clientId: "claude", projectAlias: "Mobile app", categoryId: "debugging", categoryConfidence: 0.89, classificationStatus: "classified", totalTokens: 96210, totalCost: 5.41, endedAtMs: Date.UTC(2026, 6, 22, 13, 54) },
    { sessionKey: "20ed83a7c913b5e7", installationId: "i2", clientId: "opencode", projectAlias: "Unassigned", categoryId: "research", categoryConfidence: 0.78, classificationStatus: "classified", totalTokens: 74110, totalCost: 3.86, endedAtMs: Date.UTC(2026, 6, 22, 12, 47) },
  ] as Session[],
  modelsData: {
    categoryModels: [
      { category: "implementation", model: "anthropic/claude-sonnet-4", tokens: 2300000, cost: 138.12, sessions: 108 },
      { category: "implementation", model: "openai/gpt-5-codex", tokens: 2510000, cost: 133.42, sessions: 94 },
      { category: "debugging", model: "anthropic/claude-sonnet-4", tokens: 1200000, cost: 71.36, sessions: 54 },
      { category: "debugging", model: "openai/gpt-5-codex", tokens: 1500000, cost: 78.41, sessions: 68 },
      { category: "research", model: "google/gemini-2.5-pro", tokens: 1251440, cost: 66.21, sessions: 61 },
    ] as CategoryModelBreakdown[],
    workflowModels: [
      { signal: "edited", model: "openai/gpt-5-codex", count: 142, tokens: 2100000, cost: 112.44, sessions: 72 },
      { signal: "searched", model: "anthropic/claude-sonnet-4", count: 118, tokens: 1750000, cost: 103.21, sessions: 64 },
    ] as WorkflowModelBreakdown[],
    classificationOverhead: [
      { provider: "openai-compatible", model: "small-classifier", measurement: "reported", inputTokens: 88200, outputTokens: 9100, cacheReadTokens: 12400, reasoningTokens: 0, requests: 84 },
    ] as ClassificationOverhead[],
    providers: [
      { dimension: "anthropic", tokens: 6831020, cost: 401.37, sessions: 302 },
      { dimension: "openai", tokens: 5087110, cost: 273.28, sessions: 239 },
    ] as Breakdown[],
  } as ModelsData,
  facets: {
    teams: ["engineering", "platform"],
    projects: ["Platform API", "Mobile app"],
    categories: ["implementation", "debugging", "research"],
    clients: ["claude", "codex", "opencode"],
    statuses: ["classified", "failed", "unavailable", "not_configured", "no_input"],
  } as Facets,
  adminData: {
    teams: [
      { id: "t1", name: "engineering", installations: 12, createdAt: "2026-07-01T00:00:00Z" },
      { id: "t2", name: "platform", installations: 4, createdAt: "2026-07-05T00:00:00Z" },
    ] as Team[],
    installations: [
      { id: "i1", name: "dev-workstation-01", teamId: "t1", teamName: "engineering", createdAt: "2026-07-01T00:00:00Z", lastSeenAt: "2026-07-22T12:00:00Z", lastClientVersion: "0.1.0", revoked: false },
      { id: "i2", name: "ci-runner-03", teamId: null, teamName: null, createdAt: "2026-07-03T00:00:00Z", lastSeenAt: null, lastClientVersion: null, revoked: false },
    ] as Installation[],
    settings: { organizationName: "Acme Engineering", retentionDays: 365, ssoEnforced: false, localLoginEnabled: true } as OrgSettings,
    members: [] as Member[],
    invitations: [] as Invitation[],
    classifier: { enabled: false, executionMode: "local", providerId: "", protocol: "openai_chat", endpoint: "", model: "", credentialId: "", configVersion: "disabled", credentialAvailable: false, responseMode: "auto" } as ClassifierSettings,
    credentials: [] as ProviderCredential[],
  } as AdminData,
};
