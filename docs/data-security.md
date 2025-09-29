# Data Security and Compliance Strategy

This document outlines how ShadowMap incorporates the SOC 2 and GDPR frameworks to
validate that data security requirements are established and continually satisfied.
It is intended for maintainers, contributors, and security reviewers who need a
clear picture of the technical and procedural safeguards we apply across the
project.

## Compliance Objectives

- **Protect reconnaissance data at rest and in transit** so discovery artifacts
  (domains, headers, metadata) cannot be tampered with or exfiltrated.
- **Demonstrate repeatable operational security controls** that align with
  SOC 2 Trust Services Criteria (Security, Availability, Confidentiality).
- **Respect privacy obligations under GDPR** when ShadowMap processes or stores
  personal data within recon artifacts or telemetry.
- **Maintain traceability** between implemented controls, associated evidence,
  and responsible maintainers.

## SOC 2 Integration Plan

| Control Area | Implementation in ShadowMap | Evidence & Ownership |
| --- | --- | --- |
| Logical & Network Security | Enforce TLS for all outbound integrations; document secure storage of API keys in `scripts/` helpers. | TLS enforcement tests, secret scanning CI logs (Security team). |
| Change Management | Require code review, signed commits, and successful `cargo fmt`, `clippy`, and `test` runs prior to merge. | GitHub Actions history, PR templates (Maintainers). |
| Access Controls | Limit release publishing permissions; apply least privilege to CI secrets. | GitHub role matrix, quarterly review checklist (Security team). |
| System Monitoring | Run `cargo audit` and `grype` SBOM scans on a schedule; track findings in GitHub Issues with SLA tags. | Workflow run artifacts, issue tracker exports (Maintainers). |
| Data Retention & Disposal | Provide scripts to purge generated recon data and rotate API tokens after engagements. | `scripts/cleanup.sh` logs, token rotation checklist (Ops). |

## GDPR Integration Plan

| Requirement | Implementation in ShadowMap | Evidence & Ownership |
| --- | --- | --- |
| Lawful Basis & Purpose Limitation | Default configuration stores only recon metadata required for security testing; update documentation to require customer authorization. | README usage section, engagement contracts (Legal & Ops). |
| Data Minimisation | Provide CLI flags to avoid storing raw response bodies; document anonymisation of sample outputs. | CLI help text, automated tests showing sanitized exports (Maintainers). |
| Data Subject Rights | Maintain a documented process for erasing subject data from reports upon request; ensure exports are easy to search and redact. | Incident response runbooks, audit log of deletions (Ops). |
| Security of Processing | Use encrypted storage for any long-term report hosting; encourage running ShadowMap inside hardened environments (containerization guidance). | Infrastructure-as-code repo, deployment hardening checklist (DevSecOps). |
| International Transfers | When telemetry leaves the EU, require DPAs with service providers and log transfer mechanisms (SCCs). | Vendor assessment tracker, signed DPAs (Legal). |

## Implementation Checklist

1. **Governance**
   - Assign a compliance owner to review SOC 2 and GDPR controls quarterly.
   - Track control status in a shared register (spreadsheet or GRC tool).
2. **Secure Development Lifecycle**
   - Enforce branch protection rules that require successful CI and review.
   - Extend automated tests to cover sanitisation and encryption routines.
3. **Operational Controls**
   - Configure scheduled jobs for `cargo audit` and SBOM + Grype scans.
   - Document incident response steps for suspected data exposure.
4. **Documentation & Training**
   - Update contributor onboarding with SOC 2 / GDPR responsibilities.
   - Capture evidence (screenshots, logs) after each control run.
5. **Continuous Validation**
   - Perform internal audits twice per year using this checklist.
   - Record remediation actions with owners and due dates.

## Validation Approach

- **Quarterly Control Reviews**: Run through the implementation checklist,
  capture evidence, and file tickets for gaps. Store artefacts in a dedicated
  compliance repository accessible to auditors.
- **Automated CI Reports**: Ensure every pipeline run uploads SBOM and `cargo
  audit` results, demonstrating ongoing monitoring.
- **Tabletop Exercises**: Simulate GDPR data subject requests and incident
  response scenarios to confirm procedures work end-to-end.

Keeping this document up to date is essential for preserving our security
posture. When new modules or data flows are introduced, update the relevant SOC 2
and GDPR controls, owners, and evidence expectations.
