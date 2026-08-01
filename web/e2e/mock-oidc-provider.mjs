import { createSign, generateKeyPairSync, randomBytes, createHash } from "node:crypto";
import { createServer } from "node:http";

const port = Number(process.env.METRUNE_TEST_OIDC_PORT ?? "19090");
const issuer = `http://localhost:${port}`;
const clientId = "metrune-browser-e2e";
const clientSecret = "metrune-browser-e2e-secret";
const email = process.env.METRUNE_TEST_OIDC_EMAIL ?? "admin@test.com";
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { format: "pem", type: "pkcs1" },
  publicKeyEncoding: { format: "jwk" },
});
const publicJwk = publicKey;
const pending = new Map();

function json(response, status, value) {
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  response.end(JSON.stringify(value));
}

function redirect(response, location) {
  response.writeHead(302, { location, "cache-control": "no-store" });
  response.end();
}

function encodedJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function idToken(nonce) {
  const now = Math.floor(Date.now() / 1000);
  const header = encodedJson({ alg: "RS256", kid: "metrune-browser-e2e", typ: "JWT" });
  const payload = encodedJson({
    iss: issuer,
    aud: clientId,
    exp: now + 300,
    iat: now,
    sub: "browser-e2e-enterprise-user",
    email,
    email_verified: true,
    nonce,
  });
  const unsigned = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  return `${unsigned}.${signer.sign(privateKey).toString("base64url")}`;
}

async function requestBody(request) {
  let body = "";
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 64 * 1024) throw new Error("request body too large");
  }
  return body;
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", issuer);
    if (request.method === "GET" && url.pathname === "/health") {
      return json(response, 200, { status: "ok" });
    }
    if (
      request.method === "GET" &&
      url.pathname === "/.well-known/openid-configuration"
    ) {
      return json(response, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        scopes_supported: ["openid", "email", "profile"],
        token_endpoint_auth_methods_supported: ["client_secret_basic"],
        claims_supported: ["sub", "email", "email_verified", "nonce"],
      });
    }
    if (request.method === "GET" && url.pathname === "/jwks") {
      return json(response, 200, {
        keys: [
          {
            ...publicJwk,
            kid: "metrune-browser-e2e",
            use: "sig",
            alg: "RS256",
          },
        ],
      });
    }
    if (request.method === "GET" && url.pathname === "/authorize") {
      const redirectUri = url.searchParams.get("redirect_uri");
      const state = url.searchParams.get("state");
      const nonce = url.searchParams.get("nonce");
      const codeChallenge = url.searchParams.get("code_challenge");
      const scopes = (url.searchParams.get("scope") ?? "").split(" ");
      if (
        url.searchParams.get("client_id") !== clientId ||
        url.searchParams.get("response_type") !== "code" ||
        url.searchParams.get("code_challenge_method") !== "S256" ||
        !redirectUri ||
        !state ||
        !nonce ||
        !codeChallenge ||
        !scopes.includes("openid") ||
        !scopes.includes("email")
      ) {
        return json(response, 400, { error: "invalid_request" });
      }
      const code = randomBytes(24).toString("base64url");
      pending.set(code, { nonce, codeChallenge });
      const callback = new URL(redirectUri);
      callback.searchParams.set("code", code);
      callback.searchParams.set("state", state);
      return redirect(response, callback.toString());
    }
    if (request.method === "POST" && url.pathname === "/token") {
      const expectedBasic = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
      if (request.headers.authorization !== expectedBasic) {
        return json(response, 401, { error: "invalid_client" });
      }
      const form = new URLSearchParams(await requestBody(request));
      const code = form.get("code");
      const authorization = code ? pending.get(code) : undefined;
      if (
        form.get("grant_type") !== "authorization_code" ||
        !authorization ||
        !form.get("redirect_uri")?.endsWith("/v1/auth/sso/callback")
      ) {
        return json(response, 400, { error: "invalid_grant" });
      }
      const verifier = form.get("code_verifier") ?? "";
      const actualChallenge = createHash("sha256").update(verifier).digest("base64url");
      if (actualChallenge !== authorization.codeChallenge) {
        return json(response, 400, { error: "invalid_grant" });
      }
      pending.delete(code);
      return json(response, 200, {
        access_token: "mock-browser-access-token",
        token_type: "Bearer",
        expires_in: 300,
        id_token: idToken(authorization.nonce),
      });
    }
    json(response, 404, { error: "not_found" });
  } catch (error) {
    console.error(error);
    json(response, 500, { error: "server_error" });
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`mock OIDC provider listening at ${issuer}`);
});
