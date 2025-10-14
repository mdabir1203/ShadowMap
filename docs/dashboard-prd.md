# ShadowMap Dashboard Product Requirements

## Background
ShadowMap now includes an experimental Slint-based desktop dashboard that surfaces live scan
activity and historical recon metrics. The prototype aggregates scan execution, alerting, and
subdomain discovery data to help security responders monitor progress at a glance. This PRD
formalizes the product direction so engineering can iterate beyond the prototype and deliver a
production-ready experience.

## Problem Statement
Security operations teams lack a unified view of ShadowMap scan coverage and the actionable
findings generated during continuous reconnaissance. Without a dashboard they must inspect raw
reports, CLI output, or ad-hoc spreadsheets, which slows triage and obscures whether new scans are
healthy. We need a first-class experience that answers "what is happening right now" and "what needs
attention" without forcing analysts to leave the ShadowMap ecosystem.

## Goals
- Present real-time visibility into the status of active scans, including progress, elapsed time,
  and completion state.
- Highlight the most critical findings—takeover risks, exposed services, and alert spikes—so analysts
  can prioritize follow-up.
- Summarize recent discovery metrics (subdomains, ports, fingerprints) to communicate coverage
  trends to stakeholders.
- Support switching between demo data and live scan feeds for onboarding, testing, and operational
  use.
- Provide a launch point to trigger new scans without returning to the terminal experience.

## Non-Goals
- Building a multi-user web application or SaaS deployment; this iteration remains a desktop
  experience embedded with the ShadowMap CLI.
- Replacing in-depth report views or CSV/JSON exports; the dashboard surfaces summaries and links to
  detailed artifacts generated elsewhere.
- Implementing role-based access control or audit trails; those features belong to future remote
  management initiatives.

## Target Users
- **Recon engineers** who own continuous discovery pipelines and need feedback on scan health.
- **Security incident responders** who must quickly understand which findings require urgent action.
- **Program managers or executives** who want high-level trends to report on coverage and risk.

## User Stories
1. As a recon engineer, I can launch a new scan from the dashboard, monitor its progress bar, and see
   when it completes without switching tools.
2. As an incident responder, I can identify the latest high-severity alerts and drill into the
   affected asset list to start remediation.
3. As a program manager, I can observe weekly trends in discovered subdomains and asset exposure to
   gauge improvement over time.
4. As a new user, I can explore the dashboard with demo data before connecting to live scans so I can
   evaluate capabilities without configuring infrastructure.

## Functional Requirements
- **Scan control panel**
  - Display a list of recent scans with status, duration, and target scope.
  - Provide controls to trigger a new scan and to cancel a running scan when necessary.
  - Show progress indication (percentage and elapsed time) for the active scan.
- **Metrics overview cards**
  - Surface key counts such as total subdomains discovered, takeover risks, exposed services, and
    alert volume from the most recent scan.
  - Use gradient visuals and iconography consistent with the existing prototype.
- **Trend visualizations**
  - Render a simple activity chart for discoveries over the past 7–30 days.
  - Indicate spikes or anomalies with contextual coloring or annotations.
- **Alerts and asset lists**
  - Present the top outstanding alerts with severity labels and timestamps.
  - Provide a scrollable list of affected assets (subdomains, ports, technologies) that refreshes as
    new scan data arrives.
- **Demo vs. live data toggle**
  - Allow operators to switch between static demo datasets and real-time scan feeds.
  - Persist the chosen mode between application launches when possible.
- **Error handling and offline states**
  - Communicate connectivity issues, scan failures, or missing data with actionable messaging.
  - Offer retry or re-sync actions without requiring application restarts.

## Data & Integration Requirements
- Consume scan metadata, asset counts, and alert summaries from the existing ShadowMap reporting
  pipeline exposed by `dashboard.rs`.
- Poll the filesystem or IPC channel for incremental scan updates at intervals no longer than five
  seconds to maintain a responsive UI.
- Store lightweight preferences (data mode, window layout) locally using the configuration
  facilities already present in the CLI where possible.

## Non-Functional Requirements
- The dashboard binary must remain behind the `dashboard` Cargo feature flag and build successfully
  on macOS, Linux, and Windows using the optional Slint dependency tree.
- UI interactions should remain responsive at 60 FPS for datasets up to 5,000 assets in memory.
- Loading demo data should take less than two seconds from application launch.
- Telemetry (logs, metrics) should integrate with the CLI logging subsystem for consistency.

## Milestones
1. **MVP hardening** – Align the existing prototype with the functional requirements above, close
   gaps in error handling, and ensure scan launch/cancel actions are robust.
2. **Analytics polish** – Add richer trend visualizations and configurable time ranges for activity
   charts.
3. **Advanced workflows** – Integrate deep links to report exports and introduce lightweight
   collaboration features such as sharing a snapshot of current findings.

## Open Questions
- Should the dashboard support authentication or encryption when connecting to remote scan runners?
- Do we need to support multi-target scan comparisons in a single view, or is sequential monitoring
  sufficient for the first release?
- What export formats (PDF, screenshot, JSON) do stakeholders expect directly from the dashboard?
