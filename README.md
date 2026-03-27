# pushover-mcp

Minimal stateless MCP server for sending yourself Pushover notifications.

It runs as plain Node on a single HTTP endpoint, so Railway can just start it with `npm start`.

## Env

Required:

- `PUSHOVER_APP_TOKEN`
- `PUSHOVER_USER_KEY`

Optional:

- `MCP_AUTH_TOKEN`
- `HOST`
- `PORT`
- `MCP_PATH`
- `HEALTH_PATH`
- `MAX_BODY_SIZE_BYTES`
- `PUSHOVER_DEFAULT_TITLE`
- `PUSHOVER_DEFAULT_DEVICE`
- `PUSHOVER_DEFAULT_URL`
- `PUSHOVER_DEFAULT_URL_TITLE`
- `PUSHOVER_DEFAULT_SOUND`
- `PUSHOVER_DEFAULT_PRIORITY`
- `PUSHOVER_DEFAULT_TTL`

## Tool

`ping_me`

Inputs:

- `message` required
- `title`
- `device`
- `url`
- `url_title`
- `sound`
- `priority`
- `ttl`
- `retry`
- `expire`

If `priority=2`, you must also send `retry` and `expire`.

## Run

```bash
npm install
npm start
```
