# Project: claude-agents

## What this repo is
A multi-agent Claude Code setup with 6 specialized skills for planning,
architecture, implementation, review, and testing. Use this as a base
config that gets copied into or referenced from real projects.

## Agent roster
| Skill | Invoke | Purpose |
|---|---|---|
| task-planner | /task-planner | Start here for any new feature |
| architecture-agent | /architecture-agent | Design decisions and ADRs |
| coding-agent | /coding-agent | Feature implementation |
| code-assistant | /code-assistant | Quick help, explain, debug |
| code-reviewer | /code-reviewer | Review before every commit |
| testing-expert | /testing-expert | Write and improve tests |

## Workflow rule
Always follow this order:
task-planner → architecture-agent → coding-agent → code-reviewer → testing-expert

Never skip task-planner for non-trivial work.
Never commit without running code-reviewer first.

## Code conventions
- Language: [fill in — e.g. TypeScript, Python]
- Framework: [fill in — e.g. Next.js, FastAPI]
- Test framework: [fill in — e.g. Jest, Pytest, Vitest]
- Package manager: [fill in — e.g. npm, pnpm, uv]
- Style: [fill in — e.g. ESLint + Prettier, Ruff]

## ADR location
All architecture decisions are stored in /docs/adr/
Reference them before making structural changes.

## Things Claude should always do
- Read existing files before writing any code
- Match the code style found in the codebase exactly
- Leave TODO comments for anything deferred
- Run tests after every coding task

## Things Claude should never do
- Delete existing code unless explicitly asked
- Commit without a code-review pass
- Skip writing tests for new features
- Make architectural decisions without running architecture-agent first