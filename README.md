# pushover-mcp

Minimal remote MCP server for sending yourself Pushover notifications.

It exposes a single stateless MCP endpoint and an OAuth flow that works with Claude.ai custom connectors.

## Required env

- `PUBLIC_BASE_URL`
- `PUSHOVER_APP_TOKEN`
- `PUSHOVER_USER_KEY`
- `OAUTH_SIGNING_SECRET`
- `OAUTH_APPROVAL_TOKEN`

## Useful env

- `PORT`
- `HOST`
- `MCP_PATH`
- `HEALTH_PATH`
- `MAX_BODY_SIZE_BYTES`
- `OAUTH_ALLOWED_REDIRECT_URIS`
- `OAUTH_ACCESS_TOKEN_TTL_SECONDS`
- `OAUTH_REFRESH_TOKEN_TTL_SECONDS`
- `OAUTH_CODE_TTL_SECONDS`
- `OAUTH_PENDING_AUTH_TTL_SECONDS`
- `PUSHOVER_DEFAULT_DEVICE`
- `PUSHOVER_DEFAULT_URL`
- `PUSHOVER_DEFAULT_URL_TITLE`
- `PUSHOVER_DEFAULT_SOUND`
- `PUSHOVER_DEFAULT_PRIORITY`
- `PUSHOVER_DEFAULT_TTL`

By default, dynamic client registration accepts Claude callback URLs plus ChatGPT-style OpenAI callback patterns:

- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.com/api/mcp/auth_callback`
- `https://chat.openai.com/aip/*/oauth/callback`
- `https://chatgpt.com/aip/*/oauth/callback`

If you want to test locally with a different callback, set `OAUTH_ALLOWED_REDIRECT_URIS` to a comma-separated allowlist.

For local HTTP testing only, set `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=1`.

## Tool

`ping_me` requires:

- `title`
- `message`

It also accepts `device`, `url`, `url_title`, `sound`, `priority`, and `ttl`.

Emergency priority is intentionally disabled.

## Run

```bash
npm install
npm start
```
