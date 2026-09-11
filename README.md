# HelpDeskAI — multi-tenant AI customer-support SaaS (security validation fixture)

> ## ⚠️ DELIBERATELY VULNERABLE — DO NOT USE
> This repository is a **synthetic security-scanner validation fixture**. It contains
> intentionally planted vulnerabilities (cross-tenant IDOR, SQL injection, public S3
> buckets, over-broad IAM, prompt injection, insecure CI/CD coding-agent workflows, and
> more). **Do not deploy it, do not copy any code or workflow from it, and do not treat
> any pattern here as guidance.** It exists only to be scanned.

## What this is

**HelpDeskAI** is a fictional multi-tenant SaaS where companies (*tenants*) deploy an AI
customer-support agent. Each tenant's agent answers their end-customers' questions and
takes actions on the tenant's behalf: search the tenant knowledge base, look up a
customer's orders, issue refunds, and create support tickets.

It is built to be a realistic stand-in for the kind of repository a real customer of
[Trent](https://trent.ai) might have, and is deliberately seeded with both vulnerable
and secure patterns so it can validate **all** of Trent's analyses at once:

1. **Threat model** — a conventional multi-tenant web service on AWS, carrying classical
   threats: multi-tenancy/isolation, database, storage, IAM, and auth.
2. **Agentic inventory posture** — the support agent uses an MCP server, multiple tools,
   a sub-agent, and a multi-agent handoff.
3. **Agentic deployment-automation posture** — the CI/CD runs Claude Code, OpenAI Codex,
   and a shelled-in aider agent via GitHub Actions, with a mix of safe and unsafe config.

Because the agent's tools operate on **tenant data**, the surfaces interact: a chat
prompt-injection can drive an un-tenant-scoped database tool into a cross-tenant data
leak. Those cross-surface chains are the most interesting thing here to detect.

## Architecture

```
                          end customer
                               │  POST /v1/chat  (+ JWT)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  API (FastAPI)  src/api/                                              │
│    routers/chat.py · kb.py · admin.py                                 │
│  Auth  src/auth/jwt_validator.py   (JWT → tenant context)             │
└───────────────┬───────────────────────────────────────────────────────┘
                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Support agent  src/agent/                                            │
│    orchestrator → triage sub-agent → specialist (multi-agent handoff) │
│    tools: search_kb · lookup_order · issue_refund · create_ticket     │
│    MCP server  src/mcp_server/  (execute_code, query_database)        │
└───────────────┬───────────────────────────────────────────────────────┘
                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Data layer  src/data/   (AWS backbone)                               │
│    DynamoDB  conversations · tickets · tenant config  (PK tenant_id)  │
│    RDS Postgres  orders · customers (PII)                             │
│    S3  per-tenant KB docs · attachments                              │
│    Bedrock  the LLM                                                   │
│  Infra-as-code  infra/main.tf  (buckets · table · RDS · IAM)          │
└─────────────────────────────────────────────────────────────────────┘
                ▲
                │  Claude Code · Codex · aider in GitHub Actions
        .github/workflows/   (operate ON this repo in CI/CD)
```

| Layer | Carries threats of type |
|---|---|
| `src/auth/` + `src/api/routers/` | JWT verification, tenant-context integrity, authorization |
| `src/data/` | multi-tenancy isolation, SQL injection, PII handling, presigned-URL scope |
| `infra/` | public buckets, encryption-at-rest, IAM least-privilege, committed creds |
| `src/agent/` + `src/mcp_server/` | prompt injection, RCE/SSRF tools, MCP auth, inter-agent trust |
| `.github/workflows/` | CI/CD coding-agent posture (untrusted-input, token scope, fork secrets) |

## Structure

```
src/api/                 # FastAPI app + routers (chat, kb, admin)
src/auth/                # JWT validation + tenant-context extraction
src/data/                # DynamoDB / RDS / S3 / Bedrock clients
src/agent/               # LangGraph multi-agent system + domain tools
src/mcp_server/          # FastMCP server with two tools
infra/                   # Terraform — AWS buckets, table, RDS, IAM
.claude/skills/          # Claude Code skill (deliberately insecure)
.github/workflows/       # GitHub Actions (mix of vulnerable + secure agent CI/CD)
.github/actions/         # Reusable composite action (positive control)
tests/                   # Unit tests (also document the security contract)
```

## Note for maintainers

The internal ground-truth label set (every planted vuln, positive control, expected
inventory item, and cross-surface attack chain) lives with the Trent design docs, not in
this public repo. This repo is the *realistic-looking* fixture; the answer key is kept
separately for grading.

## Running tests

```bash
poetry install
poetry run pytest tests/ -v
```

## Security

Remediation of the Trent scan findings landed in commit 4dd0e30. Remaining manual controls (branch protection, GitHub environments, OIDC roles) are tracked in the Trent project.

Last validated: 2026-09-11.
