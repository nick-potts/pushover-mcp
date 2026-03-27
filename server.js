import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import {
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import * as z from "zod/v4";

const HOST = process.env.HOST ?? "0.0.0.0";
const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const MCP_PATH = normalizePath(process.env.MCP_PATH ?? "/mcp");
const HEALTH_PATH = normalizePath(process.env.HEALTH_PATH ?? "/healthz");
const MAX_BODY_SIZE_BYTES = Number.parseInt(
  process.env.MAX_BODY_SIZE_BYTES ?? "262144",
  10,
);
const PUSHOVER_APP_TOKEN =
  process.env.PUSHOVER_APP_TOKEN ?? process.env.PUSHOVER_TOKEN ?? "";
const PUSHOVER_USER_KEY =
  process.env.PUSHOVER_USER_KEY ?? process.env.PUSHOVER_USER ?? "";
const PUSHOVER_DEFAULT_DEVICE = process.env.PUSHOVER_DEFAULT_DEVICE ?? "";
const PUSHOVER_DEFAULT_URL = process.env.PUSHOVER_DEFAULT_URL ?? "";
const PUSHOVER_DEFAULT_URL_TITLE = process.env.PUSHOVER_DEFAULT_URL_TITLE ?? "";
const PUSHOVER_DEFAULT_SOUND = process.env.PUSHOVER_DEFAULT_SOUND ?? "";
const PUSHOVER_DEFAULT_PRIORITY = process.env.PUSHOVER_DEFAULT_PRIORITY ?? "";
const PUSHOVER_DEFAULT_TTL = process.env.PUSHOVER_DEFAULT_TTL ?? "";
const PUBLIC_BASE_URL = mustUrl(
  process.env.PUBLIC_BASE_URL ?? process.env.BASE_URL ?? "",
  "PUBLIC_BASE_URL",
);
const OAUTH_SIGNING_SECRET = mustEnv("OAUTH_SIGNING_SECRET");
const OAUTH_APPROVAL_TOKEN = mustEnv("OAUTH_APPROVAL_TOKEN");
const OAUTH_ACCESS_TOKEN_TTL_SECONDS = parsePositiveInt(
  process.env.OAUTH_ACCESS_TOKEN_TTL_SECONDS ?? "3600",
  "OAUTH_ACCESS_TOKEN_TTL_SECONDS",
);
const OAUTH_REFRESH_TOKEN_TTL_SECONDS = parsePositiveInt(
  process.env.OAUTH_REFRESH_TOKEN_TTL_SECONDS ?? "2592000",
  "OAUTH_REFRESH_TOKEN_TTL_SECONDS",
);
const OAUTH_CODE_TTL_SECONDS = parsePositiveInt(
  process.env.OAUTH_CODE_TTL_SECONDS ?? "600",
  "OAUTH_CODE_TTL_SECONDS",
);
const OAUTH_PENDING_AUTH_TTL_SECONDS = parsePositiveInt(
  process.env.OAUTH_PENDING_AUTH_TTL_SECONDS ?? "900",
  "OAUTH_PENDING_AUTH_TTL_SECONDS",
);
const OAUTH_ALLOWED_REDIRECT_URIS = parseAllowedRedirectUris(
  process.env.OAUTH_ALLOWED_REDIRECT_URIS,
);
const OAUTH_SCOPES = ["mcp:tools"];
const RESOURCE_SERVER_URL = new URL(MCP_PATH, PUBLIC_BASE_URL);

if (!PUSHOVER_APP_TOKEN || !PUSHOVER_USER_KEY) {
  console.error(
    "Missing PUSHOVER_APP_TOKEN/PUSHOVER_TOKEN or PUSHOVER_USER_KEY/PUSHOVER_USER.",
  );
  process.exit(1);
}

class StatelessClaudeClientsStore {
  async getClient(clientId) {
    try {
      const payload = verifySignedValue(clientId, "client");
      validateRedirectUris(payload.redirect_uris);

      return {
        client_id: clientId,
        client_id_issued_at: payload.client_id_issued_at,
        redirect_uris: payload.redirect_uris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: payload.client_name,
        client_uri: payload.client_uri,
        logo_uri: payload.logo_uri,
        scope: payload.scope,
        contacts: payload.contacts,
        tos_uri: payload.tos_uri,
        policy_uri: payload.policy_uri,
        jwks_uri: payload.jwks_uri,
        jwks: payload.jwks,
        software_id: payload.software_id,
        software_version: payload.software_version,
        software_statement: payload.software_statement,
      };
    } catch {
      return undefined;
    }
  }

  async registerClient(client) {
    validateRedirectUris(client.redirect_uris);

    const clientIdIssuedAt = nowInSeconds();
    const payload = {
      client_id_issued_at: clientIdIssuedAt,
      redirect_uris: client.redirect_uris,
      client_name: client.client_name,
      client_uri: client.client_uri,
      logo_uri: client.logo_uri,
      scope: client.scope,
      contacts: client.contacts,
      tos_uri: client.tos_uri,
      policy_uri: client.policy_uri,
      jwks_uri: client.jwks_uri,
      jwks: client.jwks,
      software_id: client.software_id,
      software_version: client.software_version,
      software_statement: client.software_statement,
    };

    return {
      ...payload,
      client_id: signValue("client", payload),
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    };
  }
}

class PersonalOAuthProvider {
  constructor() {
    this.clientsStore = new StatelessClaudeClientsStore();
    this.pendingAuthorizations = new Map();
    this.authorizationCodes = new Map();
  }

  renderApprovalPage(res, pendingId, errorMessage) {
    const pending = this.pendingAuthorizations.get(pendingId);
    if (!pending) {
      throw new InvalidRequestError("Authorization request expired.");
    }

    const clientName = pending.client.client_name || "Claude";
    const resourceHref = pending.params.resource?.href ?? RESOURCE_SERVER_URL.href;

    res
      .status(errorMessage ? 401 : 200)
      .setHeader("Content-Type", "text/html; charset=utf-8")
      .send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Approve Claude</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f6f3ea; color: #17130f; }
      main { max-width: 34rem; margin: 4rem auto; padding: 2rem; background: #fffdf8; border: 1px solid #d9d0c4; border-radius: 16px; box-shadow: 0 12px 32px rgba(23, 19, 15, 0.08); }
      h1 { margin-top: 0; font-size: 1.5rem; }
      p, li { line-height: 1.5; }
      code { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.9em; }
      input { width: 100%; box-sizing: border-box; padding: 0.8rem 0.9rem; border: 1px solid #b9af9f; border-radius: 10px; font: inherit; }
      button { margin-top: 1rem; width: 100%; padding: 0.85rem 1rem; border: 0; border-radius: 10px; background: #1f5eff; color: white; font: inherit; font-weight: 600; cursor: pointer; }
      .error { margin: 1rem 0; padding: 0.85rem 1rem; border-radius: 10px; background: #fff0ed; color: #8a2c19; }
      .meta { color: #5d5247; font-size: 0.95rem; }
      ul { padding-left: 1.2rem; }
    </style>
  </head>
  <body>
    <main>
      <h1>Approve ${escapeHtml(clientName)}</h1>
      <p>This grants Claude access to your Pushover MCP server so it can call <code>ping_me</code> on your behalf.</p>
      <ul class="meta">
        <li>Redirect: <code>${escapeHtml(pending.params.redirectUri)}</code></li>
        <li>Resource: <code>${escapeHtml(resourceHref)}</code></li>
        <li>Scopes: <code>${escapeHtml(
          (pending.params.scopes?.join(" ") || OAUTH_SCOPES.join(" ")),
        )}</code></li>
      </ul>
      ${
        errorMessage
          ? `<div class="error">${escapeHtml(errorMessage)}</div>`
          : ""
      }
      <form method="post" action="/oauth/approve">
        <input type="hidden" name="pending_id" value="${escapeHtml(pendingId)}" />
        <label for="approval_token">Approval token</label>
        <input id="approval_token" name="approval_token" type="password" autocomplete="current-password" required />
        <button type="submit">Approve</button>
      </form>
    </main>
  </body>
</html>`);
  }

  async authorize(client, params, res) {
    this.sweepExpiredState();

    const pendingId = randomUUID();
    this.pendingAuthorizations.set(pendingId, {
      client,
      params: {
        ...params,
        scopes: params.scopes?.length ? params.scopes : OAUTH_SCOPES,
        resource: normalizeRequestedResource(params.resource),
      },
      expiresAt: nowInSeconds() + OAUTH_PENDING_AUTH_TTL_SECONDS,
    });

    this.renderApprovalPage(res, pendingId);
  }

  async completeAuthorization(pendingId, approvalToken) {
    this.sweepExpiredState();

    const pending = this.pendingAuthorizations.get(pendingId);
    if (!pending) {
      throw new InvalidRequestError("Authorization request expired.");
    }

    if (approvalToken !== OAUTH_APPROVAL_TOKEN) {
      throw new InvalidRequestError("Approval token is invalid.");
    }

    this.pendingAuthorizations.delete(pendingId);

    const code = randomUUID();
    this.authorizationCodes.set(code, {
      clientId: pending.client.client_id,
      redirectUri: pending.params.redirectUri,
      codeChallenge: pending.params.codeChallenge,
      scopes: pending.params.scopes,
      resource: pending.params.resource?.href ?? RESOURCE_SERVER_URL.href,
      expiresAt: nowInSeconds() + OAUTH_CODE_TTL_SECONDS,
    });

    const redirectUrl = new URL(pending.params.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (pending.params.state) {
      redirectUrl.searchParams.set("state", pending.params.state);
    }

    return redirectUrl.href;
  }

  async challengeForAuthorizationCode(client, authorizationCode) {
    this.sweepExpiredState();

    const codeData = this.authorizationCodes.get(authorizationCode);
    if (!codeData || codeData.expiresAt <= nowInSeconds()) {
      throw new InvalidGrantError("Authorization code is invalid or expired.");
    }

    if (codeData.clientId !== client.client_id) {
      throw new InvalidGrantError(
        "Authorization code was not issued to this client.",
      );
    }

    return codeData.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client,
    authorizationCode,
    _codeVerifier,
    redirectUri,
    resource,
  ) {
    this.sweepExpiredState();

    const codeData = this.authorizationCodes.get(authorizationCode);
    if (!codeData || codeData.expiresAt <= nowInSeconds()) {
      throw new InvalidGrantError("Authorization code is invalid or expired.");
    }

    if (codeData.clientId !== client.client_id) {
      throw new InvalidGrantError(
        "Authorization code was not issued to this client.",
      );
    }

    if (redirectUri && redirectUri !== codeData.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match the original request.");
    }

    if (resource && resource.href !== codeData.resource) {
      throw new InvalidGrantError("resource does not match the original request.");
    }

    this.authorizationCodes.delete(authorizationCode);

    return issueTokens(client.client_id, codeData.scopes, codeData.resource);
  }

  async exchangeRefreshToken(client, refreshToken, scopes, resource) {
    let claims;
    try {
      claims = verifySignedValue(refreshToken, "refresh");
    } catch {
      throw new InvalidGrantError("Refresh token is invalid.");
    }
    const now = nowInSeconds();

    if (claims.exp <= now) {
      throw new InvalidGrantError("Refresh token has expired.");
    }

    if (claims.clientId !== client.client_id) {
      throw new InvalidGrantError("Refresh token was not issued to this client.");
    }

    const requestedScopes = scopes?.length ? scopes : claims.scopes;
    if (!requestedScopes.every((scope) => claims.scopes.includes(scope))) {
      throw new InvalidScopeError("Requested scopes exceed the granted scopes.");
    }

    const normalizedResource = resource
      ? normalizeRequestedResource(resource).href
      : claims.resource;

    if (normalizedResource !== claims.resource) {
      throw new InvalidGrantError("resource does not match the refresh token.");
    }

    return issueTokens(client.client_id, requestedScopes, normalizedResource);
  }

  async verifyAccessToken(token) {
    const claims = verifySignedValue(token, "access");
    const now = nowInSeconds();

    if (claims.exp <= now) {
      throw new InvalidTokenError("Token has expired.");
    }

    if (claims.resource !== RESOURCE_SERVER_URL.href) {
      throw new InvalidTokenError("Token resource is invalid.");
    }

    return {
      token,
      clientId: claims.clientId,
      scopes: claims.scopes,
      expiresAt: claims.exp,
      resource: new URL(claims.resource),
    };
  }

  sweepExpiredState() {
    const now = nowInSeconds();

    for (const [pendingId, pending] of this.pendingAuthorizations.entries()) {
      if (pending.expiresAt <= now) {
        this.pendingAuthorizations.delete(pendingId);
      }
    }

    for (const [code, record] of this.authorizationCodes.entries()) {
      if (record.expiresAt <= now) {
        this.authorizationCodes.delete(code);
      }
    }
  }
}

function normalizePath(pathname) {
  return pathname.startsWith("/") ? pathname : `/${pathname}`;
}

function mustEnv(name) {
  const value = process.env[name] ?? "";
  if (!value) {
    console.error(`Missing ${name}.`);
    process.exit(1);
  }
  return value;
}

function mustUrl(rawValue, name) {
  if (!rawValue) {
    console.error(`Missing ${name}.`);
    process.exit(1);
  }

  let value;
  try {
    value = new URL(rawValue);
  } catch {
    console.error(`Invalid URL for ${name}.`);
    process.exit(1);
  }

  if (value.search || value.hash || value.pathname !== "/") {
    console.error(`${name} must be an origin-style URL without path, query, or hash.`);
    process.exit(1);
  }

  return value;
}

function parsePositiveInt(value, name) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    console.error(`Invalid integer for ${name}.`);
    process.exit(1);
  }
  return parsed;
}

function parseAllowedRedirectUris(value) {
  const configured = value
    ? value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)
    : [
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        "https://chat.openai.com/aip/*/oauth/callback",
        "https://chatgpt.com/aip/*/oauth/callback",
      ];

  return configured;
}

function redirectUriAllowed(redirectUri) {
  return OAUTH_ALLOWED_REDIRECT_URIS.some((pattern) => {
    if (pattern.includes("*")) {
      const escaped = pattern.replaceAll(/[.+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(`^${escaped.replaceAll("\\*", "[^/]+")}$`);
      return regex.test(redirectUri);
    }

    return pattern === redirectUri;
  });
}

function validateRedirectUris(redirectUris) {
  for (const redirectUri of redirectUris) {
    if (!redirectUriAllowed(redirectUri)) {
      throw new InvalidClientMetadataError(
        `Unapproved redirect_uri: ${redirectUri}`,
      );
    }
  }
}

function optionalString(value) {
  return value === "" ? undefined : value;
}

function optionalInt(value, name) {
  if (value === "") {
    return undefined;
  }

  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) {
    console.error(`Invalid integer for ${name}.`);
    process.exit(1);
  }

  return parsed;
}

function nowInSeconds() {
  return Math.floor(Date.now() / 1000);
}

function signValue(kind, payload) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = createHmac("sha256", OAUTH_SIGNING_SECRET)
    .update(`${kind}.${body}`)
    .digest("base64url");

  return `${kind}.${body}.${signature}`;
}

function verifySignedValue(token, expectedKind) {
  const [kind, body, signature] = token.split(".");
  if (!kind || !body || !signature || kind !== expectedKind) {
    throw new InvalidTokenError("Token format is invalid.");
  }

  const expectedSignature = createHmac("sha256", OAUTH_SIGNING_SECRET)
    .update(`${kind}.${body}`)
    .digest();
  const receivedSignature = Buffer.from(signature, "base64url");

  if (
    expectedSignature.length !== receivedSignature.length ||
    !timingSafeEqual(expectedSignature, receivedSignature)
  ) {
    throw new InvalidTokenError("Token signature is invalid.");
  }

  try {
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    throw new InvalidTokenError("Token payload is invalid.");
  }
}

function normalizeRequestedResource(resource) {
  const target = resource ? new URL(resource) : RESOURCE_SERVER_URL;
  if (target.href !== RESOURCE_SERVER_URL.href) {
    throw new InvalidRequestError("Requested resource is not allowed.");
  }
  return target;
}

function issueTokens(clientId, scopes, resourceHref) {
  const accessExp = nowInSeconds() + OAUTH_ACCESS_TOKEN_TTL_SECONDS;
  const refreshExp = nowInSeconds() + OAUTH_REFRESH_TOKEN_TTL_SECONDS;

  return {
    access_token: signValue("access", {
      clientId,
      scopes,
      resource: resourceHref,
      exp: accessExp,
    }),
    refresh_token: signValue("refresh", {
      clientId,
      scopes,
      resource: resourceHref,
      exp: refreshExp,
    }),
    token_type: "bearer",
    expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    scope: scopes.join(" "),
  };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function createMcpServer() {
  const server = new McpServer(
    {
      name: "pushover-mcp",
      version: "0.2.0",
    },
    {
      capabilities: {
        tools: {},
        logging: {},
      },
    },
  );

  server.registerTool(
    "ping_me",
    {
      title: "Ping Me",
      description:
        "Send a Pushover notification to the configured human user. This tool is meant for an AI assistant or automation to proactively notify the user about something that matters outside the chat itself, such as task completion, a failure, a blocked workflow, an important alert, or a request for attention. In most cases, set a terse `title` plus a clear `message`, and leave everything else unset. Keep both short, specific, and immediately useful. Prefer normal priority for ordinary updates. Use `device` only when intentionally targeting one device. Use `url` and `url_title` only when the notification should link somewhere helpful. Use `sound` only when overriding the user's normal default is important. Use priority `1` only when the notification should break through quiet hours. Emergency priority is intentionally not supported by this tool.",
      inputSchema: {
        message: z
          .string()
          .min(1)
          .max(1024)
          .describe("The notification text. Keep it short, specific, and immediately useful."),
        title: z
          .string()
          .min(1)
          .max(250)
          .describe("A required terse title. Use a short label like a source, task name, status, or alert type so the user can scan it quickly."),
        device: z
          .string()
          .max(25)
          .optional()
          .describe("Pushover device name. Usually leave this unset so the notification goes to all active devices. Set it only when you intentionally want a single device."),
        url: z
          .string()
          .url()
          .optional()
          .describe("Supplementary URL shown with the notification. Usually leave this unset unless the message should link to a page, dashboard, incident, or document."),
        url_title: z
          .string()
          .max(100)
          .optional()
          .describe("Label for `url`. Use this only when `url` is set. In most cases a short action label like 'Open incident' or 'View dashboard' is best."),
        sound: z
          .string()
          .max(30)
          .optional()
          .describe("Pushover sound override. Usually leave this unset and let your account default handle it. Set it only when a specific notification sound matters."),
        priority: z
          .union([z.literal(-2), z.literal(-1), z.literal(0), z.literal(1)])
          .optional()
          .describe("Pushover priority. In most cases, omit this or use `0` for normal priority. Use `-1` or `-2` for quieter notifications, and `1` for important alerts that should bypass quiet hours."),
        ttl: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Time-to-live in seconds. Usually leave this unset. Set it only when the notification becomes irrelevant after a fixed amount of time and should disappear automatically."),
      },
    },
    async (input) => {
      const resolvedPriority =
        input.priority ??
        optionalInt(PUSHOVER_DEFAULT_PRIORITY, "PUSHOVER_DEFAULT_PRIORITY");

      if (
        resolvedPriority !== undefined &&
        ![-2, -1, 0, 1].includes(resolvedPriority)
      ) {
        throw new Error(
          "Priority must be one of -2, -1, 0, or 1. Emergency priority is disabled.",
        );
      }

      const payload = new URLSearchParams({
        token: PUSHOVER_APP_TOKEN,
        user: PUSHOVER_USER_KEY,
        title: input.title,
        message: input.message,
      });

      for (const [key, value] of Object.entries({
        device: input.device ?? optionalString(PUSHOVER_DEFAULT_DEVICE),
        url: input.url ?? optionalString(PUSHOVER_DEFAULT_URL),
        url_title: input.url_title ?? optionalString(PUSHOVER_DEFAULT_URL_TITLE),
        sound: input.sound ?? optionalString(PUSHOVER_DEFAULT_SOUND),
        priority: resolvedPriority,
        ttl: input.ttl ?? optionalInt(PUSHOVER_DEFAULT_TTL, "PUSHOVER_DEFAULT_TTL"),
      })) {
        if (value !== undefined) {
          payload.set(key, String(value));
        }
      }

      const response = await fetch("https://api.pushover.net/1/messages.json", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: payload,
      });

      const data = await response.json().catch(() => null);
      if (!response.ok || data?.status !== 1) {
        return {
          content: [
            {
              type: "text",
              text:
                Array.isArray(data?.errors) && data.errors.length > 0
                  ? data.errors.join("; ")
                  : `Pushover request failed with HTTP ${response.status}.`,
            },
          ],
          isError: true,
        };
      }

      return {
        content: [
          {
            type: "text",
            text: `Sent Pushover notification${data.receipt ? ` (receipt: ${data.receipt})` : ""}.`,
          },
        ],
        structuredContent: {
          ok: true,
          request: data.request ?? null,
          receipt: data.receipt ?? null,
        },
      };
    },
  );

  return server;
}

const oauthProvider = new PersonalOAuthProvider();
const authMiddleware = requireBearerAuth({
  verifier: oauthProvider,
  requiredScopes: [],
  resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(RESOURCE_SERVER_URL),
});

const app = express();

app.set("trust proxy", 1);
app.use(express.json({ limit: MAX_BODY_SIZE_BYTES }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

app.get(HEALTH_PATH, (_req, res) => {
  res.status(200).json({ ok: true });
});

app.get("/", (_req, res) => {
  res.status(200).json({
    name: "pushover-mcp",
    endpoint: MCP_PATH,
    auth: "oauth",
    issuer: PUBLIC_BASE_URL.href,
  });
});

app.post("/oauth/approve", async (req, res) => {
  const pendingId = String(req.body.pending_id ?? "");
  const approvalToken = String(req.body.approval_token ?? "");

  if (!pendingId || !approvalToken) {
    res.status(400).send("Missing approval form fields.");
    return;
  }

  try {
    const redirectUrl = await oauthProvider.completeAuthorization(
      pendingId,
      approvalToken,
    );
    res.redirect(302, redirectUrl);
  } catch (error) {
    if (error instanceof InvalidRequestError) {
      try {
        oauthProvider.renderApprovalPage(res, pendingId, error.message);
      } catch {
        res.status(400).send(error.message);
      }
      return;
    }

    res.status(500).send("Authorization failed.");
  }
});

app.use(
  mcpAuthRouter({
    provider: oauthProvider,
    issuerUrl: PUBLIC_BASE_URL,
    resourceServerUrl: RESOURCE_SERVER_URL,
    scopesSupported: OAUTH_SCOPES,
    resourceName: "Pushover MCP",
    clientRegistrationOptions: {
      clientIdGeneration: false,
    },
  }),
);

app.post(MCP_PATH, authMiddleware, async (req, res) => {
  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request failed:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal server error",
        },
        id: null,
      });
    }
  } finally {
    void transport.close();
    void server.close();
  }
});

app.get(MCP_PATH, (_req, res) => {
  res.setHeader("Allow", "POST");
  res.status(405).json({
    error: "method_not_allowed",
  });
});

app.delete(MCP_PATH, (_req, res) => {
  res.setHeader("Allow", "POST");
  res.status(405).json({
    error: "method_not_allowed",
  });
});

app.use((_req, res) => {
  res.status(404).json({
    error: "not_found",
  });
});

const httpServer = app.listen(PORT, HOST, () => {
  console.log(`pushover-mcp listening on ${HOST}:${PORT}${MCP_PATH}`);
});

httpServer.keepAliveTimeout = 5_000;
httpServer.headersTimeout = 10_000;

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    httpServer.close(() => {
      process.exit(0);
    });
  });
}
