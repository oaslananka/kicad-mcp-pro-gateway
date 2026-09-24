# System Overview

## What Gateway is

KiCad MCP Pro Gateway is the trusted local runtime that decides **whether**
a remote AI agent or cloud service is allowed to ask the user's local
[KiCad MCP Pro](https://github.com/oaslananka/kicad-mcp-pro) installation to
do something, and under what constraints.

> KiCad MCP Pro knows how to operate KiCad.
> KiCad MCP Pro Gateway decides whether a remote actor is allowed to ask it to.

Gateway does not implement KiCad engineering logic (schematic/PCB editing,
ERC/DRC, manufacturing export). That logic lives entirely in kicad-mcp-pro,
which Gateway treats as an opaque MCP server reachable over Streamable HTTP
on `127.0.0.1:3334/mcp` (configurable). Gateway never bypasses it and never
re-implements its tools.

## Why Gateway exists

kicad-mcp-pro's own desktop shell (`src-tauri` in the main repo) currently
launches and health-checks its Python backend over plain localhost HTTP with
no authentication, session concept, or authorization model — that is
sufficient for "is my local server up" but not for "should a remote AI agent
be allowed to mutate this project." As soon as a *remote* principal (ChatGPT,
Claude, another agent) needs to reach that local server, something has to
sit in between and enforce: which device, which session, which workspace,
which capability, at which risk level, for how long, with what audit trail.
That something is Gateway. It is a new, separate component — not a
modification of kicad-mcp-pro.

## Conceptual data path

```
ChatGPT / Claude / Web / Agent
             |
             v
     KiCad MCP Cloud (future, not in this repo)
             |
       encrypted OUTBOUND connection (initiated by Gateway)
             |
             v
+--------------------------------+
| KiCad MCP Pro Gateway          |
| (this repository)              |
|                                |
| device identity   · pairing    |
| session lifecycle · workspace  |
| capability policy  · risk      |
| approvals          · audit     |
| checkpoints        · transport |
+---------------+----------------+
                |
                v   local, loopback-only, MCP Streamable HTTP client
        KiCad MCP Pro (external project, unmodified)
                |
                v
              KiCad
```

## Non-negotiable properties (see [threat-model](../security/threat-model.md))

1. No inbound internet-facing port is ever opened on the workstation.
2. Remote connectivity is always initiated outbound by Gateway.
3. Local KiCad operation keeps working with the cloud fully unavailable.
4. The cloud can never obtain arbitrary filesystem, process, shell, or
   unrestricted MCP access — every remote operation is mediated by the local
   policy engine.
5. A transport connection is not authorization. A session is not unlimited
   access. Reconnect never resurrects a revoked/expired session.

## Repository scope

This repository contains the **client side** of pairing, relay connectivity,
and session negotiation, plus the entire local trust boundary (identity,
policy, sessions, workspaces, audit, checkpoints). It does **not** contain
the hosted cloud control plane, billing, accounts database, or team features
— those are explicitly out of scope for this repository (see
[component-boundaries.md](component-boundaries.md)) and, when they exist,
will live in a separate private service that Gateway talks to only through
the `transport` abstraction.

## Current implementation status

See the top-level README for an honest, up-to-date "what works today / what
is mocked / what is not built yet" summary. This document describes the
target architecture; it does not assert that every piece described here is
finished.
