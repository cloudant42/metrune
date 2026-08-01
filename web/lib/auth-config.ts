export type AuthMethods = {
  ssoEnabled: boolean;
  passwordEnabled: boolean;
  providerName: string | null;
};

export async function getAuthMethods(): Promise<AuthMethods | null> {
  try {
    const response = await fetch(
      `${process.env.METRUNE_API_URL ?? "http://localhost:8080"}/v1/auth/methods`,
      { cache: "no-store" },
    );
    if (!response.ok) return null;
    return response.json() as Promise<AuthMethods>;
  } catch {
    return null;
  }
}
