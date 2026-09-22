# TraceGate threat model

TraceGate checks structured proposals and emits deterministic decisions. It has no tool executor and is not an operating-system sandbox. `approve` means the proposal passed the selected policy; it is not an authenticated human approval token.

## Trust assumptions

The plan is untrusted. The policy, package code, Python interpreter, and machine running TraceGate are trusted. A direct caller of `append_report` must supply trusted `evaluate_plan` output. The CLI maintains that relationship automatically. A compromised host, altered policy, or bypassed integration can invalidate every guarantee below.

## Covered checks

| Input surface | Checks |
| --- | --- |
| JSON and plan structure | File-size cap; duplicate keys rejected; finite numbers and valid Unicode; strict known fields, tool names, and primitive types; unique step IDs; step budgets |
| File proposals | Relative ASCII paths; complete-component allowlist matching; traversal, absolute paths, encoding, backslashes, and trailing spaces/dots rejected |
| HTTP proposals | Exact configured DNS name; HTTPS; default port; no URL credentials, fragments, controls, or whitespace; method allowlist; declared timeout and response-size limits |
| DNS-name configuration | Canonical ASCII labels and a letter-led final label; canonical and legacy numeric IP forms excluded |
| Decision integrity | Canonical hashes of the proposed plan and normalized policy; deterministic reports for identical input and mode |
| Audit integrity | Canonical JSONL records, sequence and previous-hash checks, record hashes, optional comparison against a separately trusted head |

Byte and timeout bounds apply to requested values, not actual work. Any rejected step rejects the full plan. The tool does not create files, issue requests, or provide partial execution.

## Responsibilities outside this package

- A file executor must use a trusted root, safe file handles, symlink defenses, platform-specific checks, and race-safe opens. A lexical `workspace/` prefix cannot establish filesystem confinement.
- An HTTP executor must validate resolved addresses, recheck every redirect, handle DNS rebinding, enforce timeouts and streaming byte limits, and apply connection-level egress policy. An allowed hostname can resolve to a private address.
- The integration must bind execution to the exact checked plan and policy, prevent mutation after validation, require authenticated human approval where needed, and prevent callers from bypassing the gate.
- Audit owners must store checkpoints independently, control log writes, define retention, and handle stale locks, partial writes, rotation, and backup. Local lock files coordinate cooperating writers; they do not exclude malicious processes.
- Applications need cumulative budgets, rate limits, authentication, authorization by user or role, and process-level resource isolation when those are requirements.

## Explicit non-guarantees

An unkeyed hash chain does not authenticate authors or timestamps. A valid suffix can be deleted, or an entire chain recomputed, without failing internal verification. Comparing against a previously trusted head detects a changed final state. The tests demonstrate both the internal-verification limitation and checkpoint detection.

Normal CLI audit records exclude raw arguments, file content, and URLs. Identifiers and diagnostic text can still contain caller input. The writer is not a redactor, and its direct API validates only the report's top-level shape.

String content in an allowed operation is data. TraceGate does not classify prompt injection, exfiltration intent, malicious code, secrets, or the semantic safety of file content. A passed plan may still be undesirable. This release has local tests and deterministic fixtures; it has no production adoption, external security audit, or completeness claim.
