const DEVELOPMENT_DASHBOARD_TOKEN = "met_dashboard_dev";

export async function register() {
  if (process.env.METRUNE_ENV !== "production") return;

  const publicApiUrl = process.env.METRUNE_PUBLIC_API_URL?.trim();
  if (!publicApiUrl?.startsWith("https://")) {
    throw new Error("METRUNE_PUBLIC_API_URL must use HTTPS in production");
  }

  if (process.env.METRUNE_DASHBOARD_TOKEN === DEVELOPMENT_DASHBOARD_TOKEN) {
    throw new Error("the development dashboard token is not allowed in production");
  }

  const releaseBaseUrl = process.env.METRUNE_CLIENT_RELEASE_BASE_URL?.trim();
  if (releaseBaseUrl && !releaseBaseUrl.startsWith("https://")) {
    throw new Error("METRUNE_CLIENT_RELEASE_BASE_URL must use HTTPS in production");
  }
}
