import { createServer } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as z from "zod/v4";

const HOST = process.env.HOST ?? "0.0.0.0";
const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const MCP_PATH = process.env.MCP_PATH ?? "/mcp";
const HEALTH_PATH = process.env.HEALTH_PATH ?? "/healthz";
const MAX_BODY_SIZE_BYTES = Number.parseInt(
  process.env.MAX_BODY_SIZE_BYTES ?? "262144",
  10,
);
const PUSHOVER_APP_TOKEN =
  process.env.PUSHOVER_APP_TOKEN ?? process.env.PUSHOVER_TOKEN ?? "";
const PUSHOVER_USER_KEY =
  process.env.PUSHOVER_USER_KEY ?? process.env.PUSHOVER_USER ?? "";
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN ?? "";
const PUSHOVER_DEFAULT_TITLE = process.env.PUSHOVER_DEFAULT_TITLE ?? "";
const PUSHOVER_DEFAULT_DEVICE = process.env.PUSHOVER_DEFAULT_DEVICE ?? "";
const PUSHOVER_DEFAULT_URL = process.env.PUSHOVER_DEFAULT_URL ?? "";
const PUSHOVER_DEFAULT_URL_TITLE = process.env.PUSHOVER_DEFAULT_URL_TITLE ?? "";
const PUSHOVER_DEFAULT_SOUND = process.env.PUSHOVER_DEFAULT_SOUND ?? "";
const PUSHOVER_DEFAULT_PRIORITY = process.env.PUSHOVER_DEFAULT_PRIORITY ?? "";
const PUSHOVER_DEFAULT_TTL = process.env.PUSHOVER_DEFAULT_TTL ?? "";

if (!PUSHOVER_APP_TOKEN || !PUSHOVER_USER_KEY) {
  console.error(
    "Missing PUSHOVER_APP_TOKEN/PUSHOVER_TOKEN or PUSHOVER_USER_KEY/PUSHOVER_USER.",
  );
  process.exit(1);
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

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, MCP-Protocol-Version, mcp-session-id");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
}

function writeJson(res, statusCode, body) {
  setCors(res);
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function requireBearerAuth(req, res) {
  if (!MCP_AUTH_TOKEN) {
    return true;
  }

  const expected = `Bearer ${MCP_AUTH_TOKEN}`;
  if (req.headers.authorization === expected) {
    return true;
  }

  writeJson(res, 401, {
    error: "unauthorized",
    message: "Missing or invalid bearer token.",
  });

  return false;
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;

  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_SIZE_BYTES) {
      const error = new Error("Request body too large.");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }

  if (chunks.length === 0) {
    return undefined;
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function createMcpServer() {
  const server = new McpServer(
    {
      name: "pushover-mcp",
      version: "0.1.0",
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
      description: "Send a Pushover notification to the configured user.",
      inputSchema: {
        message: z.string().min(1).max(1024).describe("Notification body."),
        title: z.string().max(250).optional().describe("Notification title."),
        device: z.string().max(25).optional().describe("Optional device name."),
        url: z.string().url().optional().describe("Optional supplementary URL."),
        url_title: z.string().max(100).optional().describe("Optional title for the URL."),
        sound: z.string().max(30).optional().describe("Optional Pushover sound."),
        priority: z
          .union([z.literal(-2), z.literal(-1), z.literal(0), z.literal(1), z.literal(2)])
          .optional()
          .describe("Pushover priority."),
        ttl: z.number().int().positive().optional().describe("Optional time-to-live in seconds."),
        retry: z.number().int().min(30).optional().describe("Required for emergency priority."),
        expire: z.number().int().min(30).max(10800).optional().describe("Required for emergency priority."),
      },
    },
    async (input) => {
      if (input.priority === 2 && (!input.retry || !input.expire)) {
        throw new Error("priority=2 requires both retry and expire.");
      }

      const resolved = {
        title: input.title ?? optionalString(PUSHOVER_DEFAULT_TITLE),
        device: input.device ?? optionalString(PUSHOVER_DEFAULT_DEVICE),
        url: input.url ?? optionalString(PUSHOVER_DEFAULT_URL),
        url_title: input.url_title ?? optionalString(PUSHOVER_DEFAULT_URL_TITLE),
        sound: input.sound ?? optionalString(PUSHOVER_DEFAULT_SOUND),
        priority:
          input.priority ??
          optionalInt(PUSHOVER_DEFAULT_PRIORITY, "PUSHOVER_DEFAULT_PRIORITY"),
        ttl:
          input.ttl ??
          optionalInt(PUSHOVER_DEFAULT_TTL, "PUSHOVER_DEFAULT_TTL"),
      };

      if (resolved.priority === 2 && (!input.retry || !input.expire)) {
        throw new Error("priority=2 requires both retry and expire.");
      }

      const payload = new URLSearchParams({
        token: PUSHOVER_APP_TOKEN,
        user: PUSHOVER_USER_KEY,
        message: input.message,
      });

      for (const [key, value] of Object.entries({
        title: resolved.title,
        device: resolved.device,
        url: resolved.url,
        url_title: resolved.url_title,
        sound: resolved.sound,
        priority: resolved.priority,
        ttl: resolved.ttl,
        retry: input.retry,
        expire: input.expire,
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
        const message =
          Array.isArray(data?.errors) && data.errors.length > 0
            ? data.errors.join("; ")
            : `Pushover request failed with HTTP ${response.status}.`;
        throw new Error(message);
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

async function handleMcpRequest(req, res) {
  if (!requireBearerAuth(req, res)) {
    return;
  }

  let parsedBody;
  try {
    parsedBody = await readJsonBody(req);
  } catch (error) {
    const statusCode = error?.statusCode ?? 400;
    writeJson(res, statusCode, {
      error: "invalid_request",
      message: error instanceof Error ? error.message : "Invalid request body.",
    });
    return;
  }

  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, parsedBody);
  } catch (error) {
    console.error("MCP request failed:", error);
    if (!res.headersSent) {
      writeJson(res, 500, {
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
}

const httpServer = createServer(async (req, res) => {
  setCors(res);

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.end();
    return;
  }

  if (req.url === HEALTH_PATH && req.method === "GET") {
    writeJson(res, 200, {
      ok: true,
    });
    return;
  }

  if (req.url === "/" && req.method === "GET") {
    writeJson(res, 200, {
      name: "pushover-mcp",
      endpoint: MCP_PATH,
    });
    return;
  }

  if (req.url !== MCP_PATH) {
    writeJson(res, 404, {
      error: "not_found",
    });
    return;
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    writeJson(res, 405, {
      error: "method_not_allowed",
    });
    return;
  }

  await handleMcpRequest(req, res);
});

httpServer.keepAliveTimeout = 5_000;
httpServer.headersTimeout = 10_000;

httpServer.listen(PORT, HOST, () => {
  console.log(`pushover-mcp listening on ${HOST}:${PORT}${MCP_PATH}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    httpServer.close(() => {
      process.exit(0);
    });
  });
}
