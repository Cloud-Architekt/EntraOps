# Architecture Overview

This page explains how the EntraOps GUI reads privileged access data and how GUI actions write back to the repository.

## Data Pipeline

The GUI is a read-mostly interface layered on top of the EntraOps PowerShell module. Data flows in one direction from PowerShell output files through an Express API to the React frontend, with a small number of write-back paths for configuration and classification overrides.

```
Save-EntraOpsPrivilegedEAMJson        (PowerShell module)
        |
        v
PrivilegedEAM/<System>/<System>.json  (JSON output files, one per RBAC system)
        |
        v
Express API  http://127.0.0.1:3001    (Node.js / TypeScript server in gui/server/)
        |
        +-- GET /api/dashboard   --> Dashboard screen
        +-- GET /api/objects     --> Object Browser screen
        +-- GET /api/git         --> Git History screen
        +-- ...
        |
        v
React Client  http://localhost:5173   (Vite dev server) / same origin (production)
```

### Startup Ports

| Service | Port | Notes |
|---------|------|-------|
| Express API server | `3001` (default, override with `PORT` env var) | Binds to `127.0.0.1` only - not exposed beyond localhost |
| React dev server (Vite) | `5173` | Development only; in production, Express serves the compiled client |

### Path Resolution

The server resolves all file paths relative to `ENTRAOPS_ROOT`. If `ENTRAOPS_ROOT` is not set, it autodiscovers the repo root from its own file location (`gui/server/` three levels up). The resolved root is used for all reads from `PrivilegedEAM/` and all writes to `EntraOpsConfig.json` and `Classification/`.

## GUI Action to File Written

Most GUI screens are read-only; they fetch data from `PrivilegedEAM/` JSON files and display it. The following screens write back to the repository:

| GUI Screen | User Action | API Endpoint | File(s) Written |
|------------|-------------|--------------|-----------------|
| Connect Wizard | Save tenant connection | `POST /api/connect` | `EntraOpsConfig.json` (TenantId, TenantName, AuthenticationType, ClientId fields only) |
| Settings | Save settings | `PUT /api/config` | `EntraOpsConfig.json` (full file, all fields) |
| Object Reclassification | Save tier overrides | `PUT /api/overrides` | `Classification/Overrides.json` |
| Exclusions | Add exclusion | `POST /api/exclusions` | `Classification/Global.json`, `Classification/ExclusionsNamesCache.json` |
| Exclusions | Remove exclusion | `DELETE /api/exclusions/:guid` | `Classification/Global.json`, `Classification/ExclusionsNamesCache.json` |
| Template Editor | Save global template | `PUT /api/templates/global` | `Classification/Global.json` |

**Read-only screens** (no file writes initiated by the GUI):

| GUI Screen | Data Source |
|------------|-------------|
| Dashboard | `PrivilegedEAM/<System>/<System>.json` (aggregated per RBAC system) |
| Object Browser | `PrivilegedEAM/<System>/<System>.json` |
| PowerShell Runner | Runs PS commands via `POST /api/commands`; any file changes are made by the PS module, not the GUI |
| Git History | `git log` output via `GET /api/git` |

## Component Map

```
gui/
+-- client/          React + TypeScript frontend (Vite)
|   +-- src/
|       +-- components/   Shared UI components
|       +-- pages/        One file per screen
|       +-- hooks/        Data-fetching hooks (fetch to API)
|
+-- server/          Express API (Node.js + TypeScript)
|   +-- index.ts         Entry point: registers routes, starts server
|   +-- routes/          One router per API resource (/dashboard, /objects, etc.)
|   +-- services/        Business logic (eamReader, gitLog, commands, connect)
|   +-- middleware/      Security middleware + error handler
|   +-- utils/           Shared utilities (atomicWrite, path safety)
|
+-- shared/          Types and utilities shared between client and server
    +-- types/           TypeScript interfaces (EAM objects, API responses)
    +-- utils/           Pure functions (tier name resolution, etc.)
```

### Key Service: eamReader

`gui/server/services/eamReader.ts` is the primary read path. It reads `PrivilegedEAM/<System>/<System>.json` for each active RBAC system (determined by `RbacSystems` in `EntraOpsConfig.json`), merges the arrays, and returns typed `PrivilegedObject[]` to the route handlers.

### Write Safety: atomicWrite

All file writes (config, overrides, exclusions, templates) use `gui/server/utils/atomicWrite.ts`, which writes to a `.tmp` file then renames it atomically. This prevents partial-write corruption if the process is interrupted.
