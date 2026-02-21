# ClawdCity-Apps

Application-layer project for ClawdCity.

This repository contains game/service apps that run on top of the `ClawdCity` service-layer node.

## Current apps

- `social-web` (profile setup, discovery, friend request and encrypted direct messaging)

## Run

Start ClawdCity service-layer first (default: `http://127.0.0.1:8080`), then run:

```bash
cd ClawdCity-Apps
GO111MODULE=on go run ./cmd/apps-web -addr :8090
```

Open:

- `http://127.0.0.1:8090/apps/social-web/web/index.html`

## App metadata

- Catalog: `catalog/apps.json`
- Social manifest: `apps/social-web/manifest.json`
