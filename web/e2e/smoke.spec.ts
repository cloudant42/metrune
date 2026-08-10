import { expect, test, type Page } from "@playwright/test";

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill("admin@test.com");
  await page.getByLabel("Password").fill("admin");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL("/");
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
}

test("invalid credentials fail without creating an authenticated session", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill("admin@test.com");
  await page.getByLabel("Password").fill("definitely-wrong");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByText("invalid email or password", { exact: true })).toBeVisible();
  await expect(page).toHaveURL("/login");
  await page.goto("/profile");
  await expect(page).toHaveURL(/\/login/);
});

test("every dashboard route requires a session and leaks no organization data", async ({ page }) => {
  for (const path of ["/", "/usage", "/models", "/sessions", "/admin", "/organizations", "/profile"]) {
    const response = await page.goto(path);
    await expect(page, `${path} should redirect to the sign-in form`).toHaveURL(/\/login/);
    expect(await response?.text(), `${path} must not carry organization data`).not.toContain("Acme Engineering");
  }
});

test("admin proxy routes reject unauthenticated mutations", async ({ request }) => {
  // A shared dashboard token used to stand in for a missing session here, which
  // let anonymous callers create real organization records through the proxy.
  const response = await request.post("/api/admin/teams", {
    data: { name: `anonymous-write-${Date.now()}` },
    failOnStatusCode: false,
  });
  expect(response.status()).toBe(401);
});

test("a service token in the session cookie is not accepted as a session", async ({ request }) => {
  // The API resolves dashboard service tokens before browser sessions, so the
  // proxy must refuse to forward one: it carries an organization role and no
  // user identity. No dashboard token is seeded any more, so this asserts the
  // proxy rejects a service-token-shaped cookie rather than forwarding it. A
  // live token cannot be minted here because none is reachable through the API.
  const cookie = { name: "metrune_session", value: "met_dashboard_dev", url: "http://localhost" };
  const write = await request.post("/api/admin/teams", {
    data: { name: `service-token-write-${Date.now()}` },
    headers: { cookie: `${cookie.name}=${cookie.value}` },
    failOnStatusCode: false,
  });
  expect(write.status()).toBe(401);

  const exportResponse = await request.get("/api/export?range=30", {
    headers: { cookie: `${cookie.name}=${cookie.value}` },
    failOnStatusCode: false,
  });
  expect(exportResponse.status()).toBe(401);
});

test("the development session cookie is usable over plain http", async ({ request }) => {
  // The production build sets NODE_ENV=production even in the development
  // stack, so keying `Secure` off it marked the cookie Secure over
  // http://localhost. Chrome tolerates that; Safari discards the cookie and
  // sign-in silently fails, looping back to /login.
  const response = await request.post("/api/auth/login", {
    data: { email: "admin@test.com", password: "admin" },
  });
  expect(response.status()).toBe(200);
  const setCookie = response.headersArray().filter(header => header.name.toLowerCase() === "set-cookie");
  const session = setCookie.find(header => header.value.startsWith("metrune_session="));
  expect(session, "the login response set no session cookie").toBeTruthy();
  expect(session!.value).toContain("HttpOnly");
  expect(session!.value.toLowerCase()).not.toContain("secure");
});

test("an admin exports the organization as CSV", async ({ page }) => {
  await signIn(page);
  const response = await page.request.get("/api/export?range=30");
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("text/csv");
  expect(response.headers()["content-disposition"]).toContain("metrune-sessions.csv");
  expect(await response.text()).toContain("session_key,project,client");
});

test("public identity recovery surfaces reveal no account or token state", async ({ page }) => {
  await page.goto("/forgot-password");
  await expect(page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
  await page.getByLabel("Email").fill(`unknown-${Date.now()}@example.invalid`);
  await page.getByRole("button", { name: "Send reset link" }).click();
  await expect(page.getByText("If that address belongs to an active account")).toBeVisible();

  await page.goto("/reset-password");
  await expect(page.getByRole("heading", { name: "Choose a new password" })).toBeVisible();
  await expect(page.getByText("This reset link is missing its secure token.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Update password" })).toBeDisabled();

  await page.goto("/accept-invite");
  await expect(page.getByRole("heading", { name: "Accept invitation" })).toBeVisible();
  await expect(page.getByText("This invitation link is missing its secure token.", { exact: true })).toBeVisible();
});

test("an admin can navigate, manage a team, approve a device, and sign out", async ({ page, request }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", error => pageErrors.push(error.message));
  await signIn(page);

  for (const dimension of ["category", "workflow", "status", "client", "model", "provider", "team", "project"]) {
    await page.goto(`/usage?dimension=${dimension}`);
    await expect(page.getByRole("heading", { name: "Usage explorer", level: 1 })).toBeVisible();
    await expect(page.locator(`section[aria-label="Usage by ${dimension}"]`)).toBeVisible();
  }

  await page.goto("/models");
  await expect(page.getByRole("heading", { name: "Models", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Semantic classifier overhead" })).toBeVisible();

  await page.goto("/sessions");
  await expect(page.getByRole("heading", { name: "Sessions", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Organization sessions" })).toBeVisible();
  await page.goto("/sessions/not-a-real-session");
  await expect(page.getByRole("heading", { name: "This timeline could not be opened" })).toBeVisible();

  await page.goto("/admin/pricing");
  await expect(page.getByRole("heading", { name: "Pricing", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Provider and model prices" })).toBeVisible();

  await page.goto("/organizations");
  await expect(page.getByRole("heading", { name: "Choose a workspace", level: 1 })).toBeVisible();

  await page.goto("/admin");
  await expect(page.getByRole("heading", { name: "Administration", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "Members", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Members", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Classifier & vault", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Workspace classifier" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Provider credentials" })).toBeVisible();
  await page.getByRole("button", { name: "Organization", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Retention" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Identity" })).toBeVisible();
  await page.getByRole("button", { name: "Teams & clients", exact: true }).click();

  const suffix = `${Date.now()}-${test.info().workerIndex}`;
  const teamName = `E2E team ${suffix}`;
  const renamedTeam = `Renamed E2E ${suffix}`;
  await page.getByLabel("New team name").fill(teamName);
  await page.getByRole("button", { name: "Create", exact: true }).click();
  const teamsPanel = page.locator('section[aria-labelledby="teams-title"]');
  let teamRow = teamsPanel.getByRole("row").filter({ hasText: teamName });
  await expect(teamRow).toBeVisible();

  page.once("dialog", dialog => dialog.accept(renamedTeam));
  await teamRow.getByRole("button", { name: "Rename" }).click();
  teamRow = teamsPanel.getByRole("row").filter({ hasText: renamedTeam });
  await expect(teamRow).toBeVisible();

  page.once("dialog", dialog => dialog.accept());
  await teamRow.getByRole("button", { name: "Delete" }).click();
  await expect(teamRow).toHaveCount(0);

  await page.goto("/profile");
  await expect(page.getByRole("heading", { name: "My profile", level: 1 })).toBeVisible();
  await page.getByLabel("Client name").fill(`Browser client ${suffix}`);
  await page.getByRole("button", { name: "Prepare enrollment" }).click();
  await expect(page.getByRole("status")).toContainText("metrune enroll --server");
  await expect(page.getByRole("status")).not.toContainText("--token");

  const apiUrl = process.env.METRUNE_PUBLIC_API_URL ?? "http://localhost:8080";
  const authorizationResponse = await request.post(`${apiUrl}/v1/oauth/device/authorization`, {
    form: {
      client_id: "metrune-cli",
      installation_name: `Browser approved ${suffix}`,
      platform: "linux",
    },
  });
  expect(authorizationResponse.ok()).toBeTruthy();
  const authorization = await authorizationResponse.json();
  await page.goto(`/device?user_code=${encodeURIComponent(authorization.user_code)}`);
  await expect(page.getByRole("heading", { name: "Approve a Metrune client" })).toBeVisible();
  await page.getByRole("button", { name: "Review this client" }).click();
  await expect(page.getByText(`Browser approved ${suffix}`, { exact: true })).toBeVisible();
  await expect(page.getByText(authorization.user_code, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Approve client" }).click();
  await expect(page.getByRole("heading", { name: "Client approved" })).toBeVisible();
  const tokenResponse = await request.post(`${apiUrl}/v1/oauth/token`, {
    form: {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: authorization.device_code,
      client_id: "metrune-cli",
    },
  });
  expect(tokenResponse.status()).toBe(200);
  const issued = await tokenResponse.json();
  expect(issued.access_token).toMatch(/^mti_/);

  await page.goto("/profile");
  await expect(
    page.locator('section[aria-labelledby="clients-title"]').getByText(`Browser approved ${suffix}`, { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL("/login");
  await page.goto("/profile");
  await expect(page).toHaveURL(/\/login/);
  expect(pageErrors).toEqual([]);
});

test("an admin invites a member without SMTP and that member signs in", async ({ page, browser }) => {
  // The development stack configures no mailer, so the invitation comes back as
  // a manual link. This is the whole first-run path for a self-hosted
  // workspace that has not wired up email.
  await signIn(page);
  const invited = `invitee-${Date.now()}@test.com`;
  await page.goto("/admin");
  await page.getByRole("button", { name: "Teams & clients", exact: true }).click();
  await page.getByRole("button", { name: "Members", exact: true }).click();
  await page.getByLabel("Invitation email address").fill(invited);
  await page.getByLabel("Workspace role").selectOption("viewer");
  await page.getByRole("button", { name: "Send invitation" }).click();

  const banner = page.getByRole("status").filter({ hasText: "Share this link" });
  await expect(banner).toBeVisible();
  const acceptUrl = (await banner.locator("code").innerText()).trim();
  expect(acceptUrl).toContain("/accept-invite#mti_");

  // A fresh context: the invitee is not the signed-in admin.
  const context = await browser.newContext();
  const invitee = await context.newPage();
  await invitee.goto(acceptUrl);
  await invitee.getByLabel("Display name").fill("Invited Viewer");
  await invitee.getByLabel("Password", { exact: true }).fill("a properly long password");
  await invitee.getByLabel("Confirm password").fill("a properly long password");
  await invitee.getByRole("button", { name: /Accept|Join|Create/ }).click();

  await invitee.goto("/login");
  await invitee.getByLabel("Email").fill(invited);
  await invitee.getByLabel("Password").fill("a properly long password");
  await invitee.getByRole("button", { name: "Sign in" }).click();
  await expect(invitee).toHaveURL("/");

  // A viewer can open only their own session list and export, never the
  // organization-wide branch used by administrators and analysts.
  await invitee.goto("/sessions");
  await expect(invitee.getByRole("heading", { name: "My sessions" })).toBeVisible();
  await expect(invitee.getByRole("heading", { name: "Organization sessions" })).toHaveCount(0);
  const viewerExport = await invitee.request.get("/api/export?range=30");
  expect(viewerExport.status()).toBe(200);
  expect(viewerExport.headers()["content-disposition"]).toContain("metrune-my-sessions.csv");

  // Viewer, not admin: administration stays closed.
  await invitee.goto("/admin");
  await expect(invitee.getByText("Only organization administrators can open administration.")).toBeVisible();

  await page.goto("/admin");
  await page.getByRole("button", { name: "Members", exact: true }).click();
  const memberRow = page.getByRole("row").filter({ hasText: invited });
  await expect(memberRow.getByRole("button", { name: "Reset password" })).toHaveCount(0);
  await expect(page.getByText("Without SMTP, invitation links can be delivered manually; password reset is unavailable.")).toBeVisible();
  await context.close();
});
