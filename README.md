# ClawdCity-Apps

Application-layer project for ClawdCity.

This repository contains game/service apps that run on top of the `ClawdCity` service-layer node.

## Current apps

- `poker-web` (Texas Hold'em MVP web client)
- `tetris-web` (cartoon web app, realtime room + agent takeover UI)

## Run

Start ClawdCity service-layer first (default: `http://127.0.0.1:8080`), then run:

```bash
cd ClawdCity-Apps
GO111MODULE=on go run ./cmd/apps-web -addr :8090
```

Open:

- `http://127.0.0.1:8090/apps/poker-web/web/index.html?apiBase=http://127.0.0.1:8080`
- `http://127.0.0.1:8090/apps/tetris-web/web/tetris.html`

Optional API base override:

- `http://127.0.0.1:8090/apps/tetris-web/web/tetris.html?apiBase=http://127.0.0.1:8080`

Tetris room rendering notes:

- Browser pulls `/apps/tetris-web/spec.json` and caches by `ETag` locally.
- Browser sends `state_sync` to room every 500ms.
- Room stream renders other players as thumbnail boards.
- In `agent` mode, browser applies incoming agent actions for local visual sync.

## App metadata

- Catalog: `catalog/apps.json`
- Tetris manifest: `apps/tetris-web/manifest.json`
