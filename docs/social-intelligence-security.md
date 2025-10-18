# Social Intelligence Insights for Security

This guide captures how the ShadowMap Codex Intelligence Framework incorporates
social intelligence signals into day-to-day security workflows. It documents the
agent responsibilities, guardrails, tools, and operational defaults defined in
the framework configuration so security teams can quickly understand the data
flows they are enabling.

> **Update (v1.0)** – ShadowMap now ships with this orchestration baked into the
> autonomous recon agent. Every scan emits normalized social signals, correlated
> assets, and remediation guidance that appear in the export bundle and live dashboard.
>
> * A new `<domain>_social_intelligence.json` artifact captures the full planner,
>   signal, correlation, remediation, and metric payloads beside the traditional
>   technical report outputs.
> * Operators can point `SHADOWMAP_SOCIAL_CONFIG` at an alternate YAML definition
>   to override the embedded plan without rebuilding the binary.

## Framework Configuration

```yaml
version: "1.0"
name: "ShadowMap Codex Intelligence Framework"
description: >
  Hybrid AI system combining social listening with cloud security asset intelligence.
  Powered by Codex Agents orchestrated for collection, classification, correlation, remediation, and reporting.

agents:
  - id: planner
    role: Planner
    goal: >
      Create an optimal plan of tool calls to gather evidence, classify risk, correlate with assets,
      and propose mitigations.
    prompt: |
      You are the Planner. Given a topic or signal, plan the minimal sequence of tools to collect, classify,
      correlate, remediate, and report. Prefer cheapest tools first. Limit plan to <= 6 steps.
    output_schema: planner_plan_schema
    confidence_threshold: 0.6

  - id: classifier
    role: Social Classifier
    goal: >
      Convert unstructured social or open-source data into normalized, machine-actionable security signals.
    prompt: |
      You are the Social Classifier. Given text feeds or social posts, identify type, cloud vendor,
      services, regions, indicators, severity, and confidence.
      Merge duplicates within 48h. Produce normalized JSON.
    output_schema: signal_schema
    confidence_threshold: 0.7

  - id: correlator
    role: Correlator
    goal: >
      Map each normalized signal to ShadowMap asset graph, compute risk scores, and
      identify actionable matches.
    prompt: |
      You are the Correlator. Use ShadowMap's asset_graph and vuln_scan to match
      assets with social signals. Compute risk_score and confidence.
      Penalize sandbox assets and boost prod/payments/PII-tagged ones.
    output_schema: correlation_schema
    confidence_threshold: 0.65

  - id: remediator
    role: Remediator
    goal: >
      Generate stepwise, reversible, low-impact remediations with rollback and verification.
    prompt: |
      You are the Remediator. Build playbooks that fix issues with minimal disruption.
      Always include rollback, verification, and respect change windows.
    output_schema: remediation_schema
    confidence_threshold: 0.8

  - id: reporter
    role: Reporter
    goal: >
      Create dual-view reports (executive and engineer) summarizing the signal, affected assets,
      actions, and business impact.
    prompt: |
      You are the Reporter. Generate concise summaries in plain language for executives,
      and detailed evidence + commands for engineers. Output both as JSON + markdown.
    output_schema: report_schema

schemas:
  planner_plan_schema:
    type: object
    properties:
      topic: { type: string }
      intents: { type: array, items: { type: string } }
      plan:
        type: array
        items:
          type: object
          properties:
            step: { type: integer }
            tool: { type: string }
            args: { type: object }
            why: { type: string }
      confidence: { type: number }

  signal_schema:
    type: object
    properties:
      signals:
        type: array
        items:
          type: object
          properties:
            signal_id: { type: string }
            type: { type: string }
            topic: { type: string }
            vendor_cloud: { type: array, items: { type: string } }
            services: { type: array, items: { type: string } }
            regions: { type: array, items: { type: string } }
            severity_guess: { type: string }
            confidence: { type: number }
            evidence: { type: array }
      summary: { type: string }

  correlation_schema:
    type: object
    properties:
      matches:
        type: array
        items:
          type: object
          properties:
            asset_id: { type: string }
            reasons: { type: array, items: { type: string } }
            risk_score: { type: number }
            supporting_findings: { type: array }
      coverage_stats: { type: object }
      next_best_actions: { type: array }
      confidence: { type: number }

  remediation_schema:
    type: object
    properties:
      playbook:
        type: object
        properties:
          title: { type: string }
          steps: { type: array }
          rollback: { type: array }
          verification: { type: array }
          owner: { type: object }
          change_window: { type: string }
      ticket:
        type: object
        properties:
          project: { type: string }
          title: { type: string }
          severity: { type: string }
          due_days: { type: integer }

  report_schema:
    type: object
    properties:
      executive_brief: { type: object }
      engineer_brief: { type: object }
      kb_markdown: { type: string }

guardrails:
  - id: evidence_check
    description: "Reject any claim not supported by tool output"
  - id: rollback_required
    description: "Ensure all remediation steps have rollback"
  - id: schema_validation
    description: "Validate JSON output against schema before next agent"
  - id: duplicate_filter
    description: "Suppress repeated findings or assets"

tools:
  - name: social_feed.fetch
    description: "Collect public signals from X, GitHub, Reddit, etc."
  - name: nvd_cve.search
    description: "Search NVD for matching CVEs or CWEs."
  - name: asset_graph.search
    description: "Query internal ShadowMap asset graph."
  - name: vuln_scan.query
    description: "Get live vulnerability findings."
  - name: cloud_cfg.check
    description: "Verify cloud config policies."
  - name: notify.create
    description: "Open ticket in incident tracker."
  - name: page.create
    description: "Write report to knowledge base."

defaults:
  org_filters:
    env: ["prod", "staging"]
    regions: ["ap-south-1", "asia-south1"]
  controls_available: ["scp", "config_rules", "security_hub"]
  change_windows: ["Sun 02:00-04:00 BST"]
  localization:
    geo: "Bangladesh"
    languages: ["en", "bn"]

testing:
  scenarios:
    - name: redis_exploit
      topic: "Unauthenticated Redis 6379 exploit ap-south-1"
      expected_output: ["plan", "signals", "correlation", "remediation", "report"]
    - name: s3_public_acl
      topic: "Public S3 bucket misconfig leak"
    - name: iam_mfa_fatigue
      topic: "IAM console MFA fatigue attacks"
```

## Security-Focused Interpretation

- **Planner, Classifier, Correlator, Remediator, Reporter**: Each agent provides
  a discrete control point with explicit confidence thresholds. Security teams
  can map these agents to existing detection and response swim lanes to ensure
  accountability when social chatter hints at emerging threats.
- **Schemas and Guardrails**: Strong schema validation and evidence checks
  ensure that unstructured social data is transformed into auditable security
  artifacts before triggering automation. The rollback guardrail enforces change
  control discipline for any remediation playbook generated by the framework.
- **Tooling Inventory**: Tool selections bridge open-source intelligence
  (social feeds, NVD) with ShadowMap's internal asset graph, vulnerability
  scanners, and notification systems. This creates an end-to-end path from
  discovery to ticketing without bypassing governance.
- **Operational Defaults**: Environment and region filters prioritize production
  and staging assets in South Asia, aligning with the `Bangladesh` localization
  profile. Listed controls (`scp`, `config_rules`, `security_hub`) highlight the
  enforcement mechanisms expected to be available during remediation.
- **Testing Scenarios**: Representative incident simulations—Redis exploits, S3
  exposures, IAM MFA fatigue—allow security engineers to validate correlation
  logic and downstream automations against high-impact cloud attack patterns.

Integrate this configuration into the ShadowMap automation pipelines wherever
social intelligence monitoring feeds new leads into security operations. Keeping
the YAML under version control alongside this documentation ensures that
updates to agent prompts, guardrails, or defaults remain transparent to the
teams who depend on them.
