# TraceGate — portfolio project, September 2026

Use these only after reviewing the implementation and being comfortable explaining its design. This is a newly scaffolded project built with coding-assistant support, not prior employment or production usage.

- Built a Python policy-evaluation CLI for structured agent tool plans, enforcing strict tool schemas, component-based path allowlists, exact-host HTTPS rules, and per-operation resource limits without external runtime dependencies.
- Implemented canonical JSON decision hashes and a verifiable JSONL audit chain with externally supplied checkpoints to detect record modification, reordering, and tail truncation relative to a trusted head.
- Validated the package with 50 passing unit/integration tests and 25 deterministic replay fixtures covering malformed inputs, traversal attempts, hostname confusion, boundary conditions, and audit tampering.

**Interview distinction:** TraceGate validates proposed operations; it does not execute them or provide an operating-system sandbox. Approval, runtime enforcement, DNS/redirect handling, and trusted checkpoint storage remain integration responsibilities.
