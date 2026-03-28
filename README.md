# claude-agents

A multi-agent Claude Code setup with 6 specialized skills for planning, architecture,
implementation, review, and testing — demonstrated through a production-grade JWT auth
system built entirely by the agent workflow.

## Quick Start

```bash
pnpm install
pnpm test          # run all 70 tests
```

Set the required environment variable before starting the server:

```bash
export JWT_SECRET="your-secret-here"   # required — server exits if missing
export PORT=3000                        # optional, default 3000
export LOG_LEVEL=info                   # optional, default info
export REFRESH_TOKEN_TTL_DAYS=7        # optional, default 7
```

```bash
pnpm start
```

## Agent Roster

| Skill | Invoke | Purpose |
|---|---|---|
| task-planner | `/task-planner` | Break down work into tasks with dependencies |
| architecture-agent | `/architecture-agent` | Write ADRs, design system structure |
| coding-agent | `/coding-agent` | Implement features from ADRs |
| code-assistant | `/code-assistant` | Quick edits, explanations, small writes |
| code-reviewer | `/code-reviewer` | Security and quality review before commits |
| testing-expert | `/testing-expert` | Write and improve Jest tests |

## Workflow

```
/task-planner  →  /architecture-agent  →  /coding-agent  →  /code-reviewer  →  /testing-expert
```

Never skip `/task-planner` for non-trivial work. Never commit without `/code-reviewer`.

## Project: JWT Auth System

The repo ships a complete Fastify auth API as a worked example of the agent workflow.
See [`docs/summary/`](docs/summary/) for a full step-by-step walkthrough of how it
was built.

### API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | No | Create account; returns access token + refresh cookie |
| POST | `/auth/login` | No | Verify credentials; returns access token + refresh cookie |
| POST | `/auth/refresh` | No (cookie) | Rotate refresh token; returns new access token |
| POST | `/auth/logout` | Yes | Revoke access + refresh tokens |
| GET | `/auth/me` | Yes | Return authenticated user context |

### Architecture Decisions

All design decisions are documented in [`docs/adr/`](docs/adr/):

| ADR | Decision |
|---|---|
| [ADR-001](docs/adr/ADR-001-auth-system.md) | Hybrid JWT + httpOnly refresh token + revocation store |
| [ADR-002](docs/adr/ADR-002-session-store-abstraction.md) | ISessionStore interface + InMemorySessionStore |
| [ADR-004](docs/adr/ADR-004-revocation-store-abstraction.md) | IRevocationStore interface + InMemoryRevocationStore |
| [ADR-005](docs/adr/ADR-005-json-schema-validation.md) | Fastify JSON Schema validation on auth bodies |
| [ADR-006](docs/adr/ADR-006-rate-limiting-strategy.md) | @fastify/rate-limit per-route limits |

## Stack

- **Runtime**: Node.js
- **Framework**: Fastify
- **Language**: TypeScript
- **Tests**: Jest (70 tests, 4 suites)
- **Package manager**: pnpm
- **Style**: ESLint + Prettier
