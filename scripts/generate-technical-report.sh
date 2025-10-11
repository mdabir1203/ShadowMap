#!/usr/bin/env bash
set -euo pipefail

out_dir=${1:-build}
out_markdown="${out_dir}/technical-report.md"

mkdir -p "${out_dir}"

cat <<'EOF' > "${out_markdown}"
# ShadowMap Reconnaissance Technical Report

## Document Control
| Version | Date       | Author    | Notes                 |
|---------|------------|-----------|-----------------------|
| 1.0     | 2025-09-10 | AI Writer | Initial publication.  |

## Executive Summary
- ShadowMap completed six reconnaissance runs across enterprise and sample targets between 7 and 10 September 2025.
- The engine discovered 118 subdomains in total, validating 97 (82%) of them with live HTTP responses.
- Only one potential takeover surface was detected (Atlassian support host), while CORS misconfigurations persisted on selected bkash.com and canva.com assets.
- Bybit's footprint exposed two open network ports that warrant service fingerprinting, but no immediate takeover or CORS issues were observed.

## Objectives
1. Quantify ShadowMap's coverage of target subdomain inventories and live service footprint.
2. Highlight exploitable conditions (takeover risk, CORS exposure, open ports) that demand remediation.
3. Provide directional KPIs and governance recommendations that align reconnaissance outcomes with enterprise risk reduction goals.

## Methodology
1. **Discovery orchestration.** ShadowMap aggregated passive certificates (CRT.sh) and complementary sources, normalized IDNs, and deduplicated wildcard entries prior to scanning.【F:README.md†L10-L24】
2. **Validation & enrichment.** The framework resolved DNS, issued HTTP requests, and captured headers, TLS characteristics, and takeover heuristics to classify each asset.【F:README.md†L12-L16】
3. **Output management.** CSV, JSON, and TXT exports were generated per run for downstream analytics, mirroring the automation patterns documented in the repository workflows.【F:README.md†L18-L20】【F:README.md†L66-L91】
4. **Security posture alignment.** Findings were cross-referenced with the Data Security and Compliance Strategy, Application Governance Integration guidance, and Organizational Adoption Playbook to contextualize operational requirements.【F:README.md†L93-L118】

## Data Overview
| Target & Run (UTC) | Subdomains Discovered | Valid HTTP Responses | CORS Findings | Takeover Flags | Unique Open Ports |
|--------------------|-----------------------|----------------------|---------------|----------------|-------------------|
| atlassian.net (2025-09-07 07:39) | 6 | 5 | 0 | 1 | 0 |
| bkash.com (2025-09-07 07:16) | 42 | 33 | 5 | 0 | 0 |
| bkash.com (2025-09-08 23:09) | 44 | 34 | 4 | 0 | 0 |
| bybit.eu (2025-09-10 00:11) | 1 | 1 | 0 | 0 | 2 |
| canva.com (2025-09-08 23:37) | 24 | 23 | 1 | 0 | 0 |
| example.com (2025-09-07 06:13) | 1 | 1 | 0 | 0 | 0 |

**Totals:** 118 discovered / 97 validated / 10 CORS issues / 1 takeover flag / 2 unique open ports. Metrics are derived from the exported CSVs for each run.【F:recon_results/atlassian.net_20250907_073950/atlassian.net_report.csv†L1-L7】【F:recon_results/bkash.com_20250907_071603/bkash.com_report.csv†L1-L6】【F:recon_results/bkash.com_20250908_230919/bkash.com_report.csv†L1-L6】【F:recon_results/bybit.eu_20250910_001148/bybit.eu_report.csv†L1-L2】【F:recon_results/canva.com_20250908_233736/canva.com_report.csv†L1-L5】【F:recon_results/example.com_20250907_061338/example.com_report.csv†L1-L2】

## KPI Interpretation
- **Discovery Coverage Rate** = Validated subdomains ÷ Discovered subdomains. A sustained ~82% rate indicates ShadowMap's passive + active pipeline is resolving most enumerated assets, focusing remediation on responsive systems.
- **Potential Takeover Exposure** pinpoints hosts matching known provider signatures without ownership proof. The single Atlassian risk should trigger registrar verification and host reclamation.
- **CORS Misconfiguration Density** highlights opportunities for data exfiltration; clusters on bkash.com imply policy reviews for payment domains.
- **Service Exposure Breadth** counts distinct open ports to prioritize service fingerprinting. Bybit's two exposed ports should undergo rapid investigation per the recon workflow.

## Key Findings
1. **Atlassian support host takeover risk.** The flagged record requires DNS ownership validation to prevent hostile hijacking.【F:recon_results/atlassian.net_20250907_073950/atlassian.net_security_findings.txt†L1-L6】
2. **Payment platform CORS debt.** Nine combined CORS issues across bkash.com runs represent repeatable misconfigurations in high-sensitivity namespaces.【F:recon_results/bkash.com_20250907_071603/bkash.com_security_findings.txt†L1-L6】【F:recon_results/bkash.com_20250908_230919/bkash.com_security_findings.txt†L1-L6】
3. **Edge hardening success for bybit.eu.** Minimal footprint and no web misconfigurations suggest the service is tightly controlled, with remaining risk constrained to two open ports for review.【F:recon_results/bybit.eu_20250910_001148/bybit.eu_report.csv†L1-L2】
4. **Operational repeatability.** Consecutive bkash.com scans produced comparable coverage, demonstrating ShadowMap's consistency and readiness for scheduled governance integration.【F:recon_results/bkash.com_20250907_071603/bkash.com_report.csv†L1-L2】【F:recon_results/bkash.com_20250908_230919/bkash.com_report.csv†L1-L2】

## Recommendations
1. **Coordinate takeover remediation** via DNS and certificate management owners, leveraging the Organizational Adoption Playbook to assign executive sponsors and escalation paths.【F:docs/org-adaptation.md†L1-L94】
2. **Enforce CORS policies** on bkash.com and canva.com through automated CI/CD checks aligned with the Data Security Strategy's control owners and evidence expectations.【F:docs/data-security.md†L1-L110】
3. **Extend governance automation** by feeding validated inventories into CMDB and observability pipelines per the Application Governance Integration guide, ensuring persistent monitoring of exposed services.【F:docs/app-governance-integration.md†L1-L138】
4. **Institutionalize SBOM-driven scans** using the provided GitHub Action so vulnerability management receives updated intelligence after each recon iteration.【F:README.md†L119-L145】

## Next Steps
- Schedule a remediation sprint focused on the Atlassian takeover alert and outstanding CORS gaps.
- Integrate ShadowMap's exports with security analytics for automated alerting on new takeover heuristics.
- Refresh this report monthly, capturing trend deltas across KPIs and remediation SLAs.

## Appendices
- **Data Artifacts:** CSV, JSON, and TXT exports for each target under `recon_results/` support deeper analysis and audit retention, such as the `canva.com` scan outputs.【F:recon_results/canva.com_20250908_233736/canva.com_report.csv†L1-L5】
- **Automation Assets:** Review `.github/workflows/security-scan.yml` to align recon cadence with SBOM security checks.【F:README.md†L119-L145】
EOF
