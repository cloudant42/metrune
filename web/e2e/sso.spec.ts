import { expect, test } from "@playwright/test";

test.skip(!process.env.METRUNE_E2E_SSO, "requires the isolated OIDC E2E stack");

test("enterprise SSO signs into the web app and approves a native client", async ({
  page,
  request,
}) => {
  const apiUrl = process.env.METRUNE_PUBLIC_API_URL ?? "http://localhost:18081";
  const pageErrors: string[] = [];
  page.on("pageerror", error => pageErrors.push(error.message));

  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Sign in to Metrune" })).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Continue with Test Enterprise SSO" }),
  ).toBeVisible();
  await expect(page.getByLabel("Email")).toHaveCount(0);
  await expect(page.getByLabel("Password")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Forgot your password?" })).toHaveCount(0);
  await expect(
    page.getByText("Metrune does not accept passwords while single sign-on is configured."),
  ).toBeVisible();

  await page.getByRole("link", { name: "Continue with Test Enterprise SSO" }).click();
  await expect(page).toHaveURL("/");
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();

  await page.goto("/admin");
  await page.getByRole("button", { name: "Organization", exact: true }).click();
  const identity = page.locator('section[aria-labelledby="identity-title"]');
  await expect(identity.getByText("Local password sign-in")).toBeVisible();
  await expect(identity.getByText("disabled", { exact: true })).toBeVisible();
  await expect(identity.getByText("SSO enforcement")).toBeVisible();
  await expect(identity.getByText("enforced", { exact: true })).toBeVisible();

  const suffix = `${Date.now()}-${test.info().workerIndex}`;
  const authorizationResponse = await request.post(
    `${apiUrl}/v1/oauth/device/authorization`,
    {
      form: {
        client_id: "metrune-cli",
        installation_name: `SSO approved ${suffix}`,
        platform: "linux",
      },
    },
  );
  expect(authorizationResponse.ok()).toBeTruthy();
  const authorization = await authorizationResponse.json();
  await page.goto(`/device?user_code=${encodeURIComponent(authorization.user_code)}`);
  await page.getByRole("button", { name: "Review this client" }).click();
  await expect(page.getByText(`SSO approved ${suffix}`, { exact: true })).toBeVisible();
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
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL("/login");
  await page.goto("/forgot-password");
  await expect(page).toHaveURL("/login");
  await expect(
    page.getByRole("link", { name: "Continue with Test Enterprise SSO" }),
  ).toBeVisible();
  expect(pageErrors).toEqual([]);
});
