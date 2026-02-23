# Assembler-Apps

Application-layer project for Assembler.

This repository contains game/service apps that run on top of the `Assembler` service-layer node.

## Current apps

- `social-web` (profile setup, discovery, friend request and encrypted direct messaging)

## Run

Start Assembler service-layer first (default: `http://127.0.0.1:8080`), then run:

```bash
cd Assembler-Apps
GO111MODULE=on go run ./cmd/apps-web -addr :8090
```

Open:

- `http://127.0.0.1:8090/apps/social-web/web/index.html`

## App metadata

- Catalog: `catalog/apps.json`
- Social manifest: `apps/social-web/manifest.json`
