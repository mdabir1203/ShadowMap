# Product Requirements: Reachability-Aware Grype Enforcement

## Overview
This document captures the requirements for expanding the project's container vulnerability scanning so that CI/CD pipelines enforce Grype findings, highlight CORS anomalies, and respect reachability analysis.

## Problem Statement
The current security scan allows vulnerabilities to slip through when their severity is medium or higher. Additionally, reports lack context on whether vulnerable code paths are actually invoked, and CORS guidance is not surfaced alongside reachability data. Stakeholders need deterministic CI failures when exploitable vulnerabilities are present and actionable intelligence explaining which findings are reachable.

## Goals
- Fail CI pipelines when `grype` detects vulnerabilities at or above a configurable severity threshold (default: `medium`).
- Support a reachability-aware post-processing step that annotates vulnerabilities with `reachable` / `unreachable` evidence and suppresses enforcement when every high-severity finding is unreachable.
- Emit the standardized message `Analyse CORS controls` with the `CORS anomalies flagged on 4 hosts` status whenever reachable CORS issues remain.
- Provide artifacts (JSON reports, console summaries) that developers can audit locally and in CI.

## Non-Goals
- Replacing Grype with an alternative scanner.
- Implementing full program analysis beyond text-based reachability heuristics.
- Automatically opening remediation tickets or applying patches.

## Key Users
- **Security engineers** who need CI to fail on actionable findings.
- **Developers** who triage reports and need to know which vulnerabilities have reachable call sites.
- **Release managers** who require predictable enforcement before deploying.

## User Stories
1. As a security engineer, I can configure the fail-on severity in the reusable GitHub Action so the pipeline enforces my policy.
2. As a developer, I can review a Grype JSON report where each vulnerability entry includes reachability metadata and, when applicable, an `unreachable` tag.
3. As a developer, I receive explicit console guidance (`Analyse CORS controls`) whenever reachable CORS-related vulnerabilities remain after post-processing.
4. As a release manager, I see the pipeline fail when `grype ubuntu:latest --fail-on medium` detects reachable vulnerabilities at the enforced threshold.

## Functional Requirements
- The reusable GitHub Action accepts inputs for:
  - `fail-on-severity` (string; default `medium`).
  - `enable-reachability-analysis` (boolean; default `true`).
- The workflow must run `grype ubuntu:latest --fail-on <fail-on-severity>` as a dedicated job that fails the pipeline when the exit status is non-zero.
- `scripts/security-scan.sh` must:
  - Forward severity and reachability flags to Grype.
  - Capture Grype's JSON output and exit status.
  - Invoke `scripts/grype-postprocess.py` with the captured report and exit code.
  - Exit with the post-processor's return code after applying reachability overrides.
- `scripts/grype-postprocess.py` must:
  - Annotate vulnerabilities with reachability metadata by grepping the source tree for known vulnerable symbol names.
  - Tag entries without matching call sites as `unreachable`.
  - Preserve Grype's failure exit code when reachable vulnerabilities remain.
  - Emit the standardized CORS guidance when reachable CORS issues exist.

## Non-Functional Requirements
- The post-processing script should be lightweight (Python 3 standard library only) and run within typical CI timeouts (<60s on medium repos).
- Reports must be deterministic for the same source tree and Grype database version.
- All scripts must pass shellcheck / py_compile linting as part of CI quality gates.

## Dependencies & Risks
- Requires access to the Grype vulnerability database during CI runs.
- Reachability heuristics rely on symbol names supplied by Grype; changes upstream could reduce accuracy.
- False negatives are possible when vulnerable code is invoked indirectly or via reflection.

## Metrics & Telemetry
- Track the number of CI failures triggered by Grype severity enforcement.
- Track the count of vulnerabilities tagged as unreachable vs reachable per run.
- Monitor occurrences of the CORS guidance message to ensure follow-up investigations.

## Rollout Plan
1. Land scripts and workflow updates behind configuration defaults (`fail-on-severity=medium`, reachability enabled).
2. Validate in staging CI with sample vulnerable repositories.
3. Roll out to production branches once false positive rate is acceptable.
4. Document remediation steps for developers in README or runbook.

## Open Questions
- Should we allow per-repo overrides for the list of vulnerable function signatures?
- Do we need to upload annotated reports as CI artifacts for long-term auditing?

