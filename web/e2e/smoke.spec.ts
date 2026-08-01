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
  await expect(page.getByText("Demo data")).toHaveCount(0);

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
