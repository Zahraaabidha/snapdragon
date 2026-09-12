# ContextFence

**A privacy-first, on-device security boundary for AI-enabled Windows PCs.**

ContextFence evaluates actions taken by AI agents and AI-enabled applications
before they happen, and produces one authoritative security decision:

- **ALLOW** — the action proceeds unchanged.
- **ASK** — the user is shown structured security facts and must approve.
- **DENY** — the action is blocked.
- **SANITIZE** — the action proceeds only after configured sensitive fields are removed or masked.

Decisions are made by a deterministic **Policy Engine**, using evidence from
local security analysis. An AI model may contribute *evidence*; it never makes
the authorization decision.

---

## The problem

AI coding assistants and agentic tools can read files, run commands, call tools,
and send data to remote services on a user's behalf. That is useful, but it also
means a single confused or manipulated step can:

- leak secrets (`.env` files, API keys, tokens) into a prompt or a network call,
- disclose personal data (PII) to an external service,
- act with more authority than the user intended,
- be steered by prompt injection hidden in a file, web page, or tool response.

Existing guardrails often live *inside* the model or the application being
protected, and frequently "fail open" — if the check is uncertain or
unavailable, the action is allowed anyway.

ContextFence puts a small, deterministic, inspectable decision boundary
*outside* the agent, on the user's own machine.

---

## High-level architecture

```
Event Sources (adapters)
        |
        v
   Event Gateway            normalize into a canonical SecurityEvent
        |
        v
 Security Analysis
   |-- Deterministic Analysis   secret / PII / destination / capability detectors
   |-- Semantic Analysis        optional local model, produces evidence only
        |
        v
  Risk Aggregator          combine evidence into a structured risk view
        |
        v
   Policy Engine           deterministic, inspectable, authoritative
        |
        v
     Decision  -> ALLOW | ASK | DENY | SANITIZE
        |
        v
  Enforcement             apply the decision (allow / block / prompt / sanitize)
        |
        v
     Audit                privacy-preserving, tamper-evident record
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for component responsibilities and trust
boundaries, and [PROJECT_SPEC.md](PROJECT_SPEC.md) for scope and requirements.

---

## Why on-device inference matters

ContextFence inspects exactly the data that is most sensitive: prompts, file
contents, tool arguments, and outbound payloads. Sending that content to a
remote service for analysis would create the very exposure the product exists to
prevent.

Therefore semantic analysis, when used, runs **locally**:

- The deterministic detectors are pure local code and always run.
- The optional semantic analyzer runs through an `InferenceProvider` abstraction
  with a **CPU backend** (the development and portability fallback) and, later, a
  **Snapdragon / NPU backend** for acceleration.

The security core does not depend on any specific inference provider.

---

## The intended Snapdragon / NPU role

On Snapdragon X-class Windows devices, the NPU can accelerate the local semantic
model so that richer analysis stays fast and power-efficient without leaving the
device.

The NPU is **only an inference accelerator** for the semantic analyzer. It is
not the Policy Engine and never makes decisions. NPU execution has **not** been
validated yet; no benchmark numbers exist yet. See
[DEVELOPMENT.md](DEVELOPMENT.md) for the planned validation workflow.

---

## Current MVP scope

The first integration is **Claude Code**, connected through a ContextFence
*adapter*. Claude Code is the first adapter, not the product.

**In scope for the MVP**

- Canonical `SecurityEvent` and `Evidence` models.
- Deterministic detectors: secrets, PII, destination classification, requested capabilities.
- Risk aggregation.
- Deterministic Policy Engine with ALLOW / ASK / DENY / SANITIZE.
- Enforcement for those four outcomes.
- Privacy-preserving audit log.
- A single Claude Code adapter.
- A structured approval UI (PySide6) that renders facts produced by the core.

**Not in scope for the MVP**

- OS-wide or kernel-level enforcement.
- Filesystem, clipboard, browser, and MCP adapters (documented as future work).
- A validated Snapdragon/NPU backend.
- Any claim of complete protection against prompt injection or data loss.

See [PROJECT_SPEC.md](PROJECT_SPEC.md) for the full scope statement and
[THREAT_MODEL.md](THREAT_MODEL.md) for threats and residual risk.

---

## Current development status

**Implemented:** the framework-agnostic security core — canonical
`SecurityEvent` / `Evidence` / `RiskView` / `Decision` models and the Event
Gateway; deterministic detectors (secrets, PII, destination, capability); risk
aggregation; the deterministic Policy Engine and default policy; enforcement
(allow / deny / approval / sanitize); the privacy-preserving, tamper-evident
audit log; the provider-independent AI-adapter boundary with **Claude Code as
the first reference adapter**; the generic security pipeline that wires these
together; and a semantic-analysis **contract** — `SemanticAnalyzer` plus a
model-independent `InferenceProvider` interface with a strictly validated
result schema. See [docs/ADAPTERS.md](docs/ADAPTERS.md).

**Not implemented yet:** any concrete inference backend (no real ML model runs
yet — Phase 8 ships the semantic-analysis contract only, exercised in tests by
a deterministic fake provider; CPU and Snapdragon/NPU backends are Phase 9/10),
the evaluation/benchmark suite, and the desktop UI.

**Adapter limitation:** ContextFence does **not** currently intercept live
Claude Code activity. The Claude Code adapter translates a structured
native-event boundary; wiring a real event source is future work. There is no
OS-wide or kernel-level enforcement. NPU execution has not been validated and no
benchmark numbers exist.

Implementation proceeds in the phased order described in
[DEVELOPMENT.md](DEVELOPMENT.md). Nothing here should be read as a description of
shipped, independently validated behavior.

---

## Technology direction

- Python, typed, standard library first.
- `pytest` for tests.
- PySide6 for the desktop UI **only** — the core is independent of it.
- Validated configuration and structured logging.
- No database, no web application, no microservices, no network services in the MVP.

---

## Repository layout

```
CLAUDE.md            authoritative project instructions
ARCHITECTURE.md      intended architecture and trust boundaries
PROJECT_SPEC.md      product specification and scope
THREAT_MODEL.md      assets, threats, mitigations, residual risk
DEVELOPMENT.md       methodology, phases, testing, benchmarking
SECURITY.md          security invariants and handling rules
src/contextfence/    security core, adapters, pipeline, semantic contract (Phases 1-8)
tests/               unit + integration tests
docs/                supplementary documentation
```

---

## License

Not yet selected. To be decided before any public release.
