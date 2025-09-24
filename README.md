# ShadowMap

<img width="384" alt="ShadowMap logo" src="https://github.com/user-attachments/assets/95d39e5e-d51c-4eb4-9053-2db1e1042410" />

ShadowMap maps the cloud attack surface across AWS, Azure, and GCP so security teams and bug bounty hunters can spot risky assets before adversaries do. Everything runs from the command line—no coding required.

---

## Why teams choose ShadowMap

- **Complete visibility** – Unifies managed DNS, storage, edge, and serverless endpoints across the three major clouds.
- **Trustworthy validation** – Confirms exposure with live DNS/HTTP/TLS checks and flags misconfigurations that matter.
- **Actionable reporting** – Exports CSV/JSON/Markdown plus GPT-4 assisted briefs for fast stakeholder-ready updates.

## What ShadowMap discovers

| Cloud | High-value targets | Validation highlights |
| --- | --- | --- |
| **AWS** | Route53 zones, API Gateway, CloudFront, ALB/NLB, S3, Lambda URLs, Amplify | SigV4-aware checks, public bucket detection, dangling DNS identification |
| **Azure** | DNS Zones, App Service, Functions, Front Door, Storage, CDN, API Management | Managed identity exposure, default hostname reachability, blob ACL review |
| **GCP** | Cloud DNS, Cloud Run, Cloud Functions, Cloud Storage, Load Balancers, Firebase Hosting | IAM boundary review, anonymous invoke detection, certificate fingerprinting |

---

## Get started in minutes

If you are new to terminal tools, copy each block below into your shell one at a time.

### 1. Prepare read-only cloud access

- **AWS** – `aws sso login --profile security-audit`
- **Azure** – `az login --tenant <tenant_id>`
- **GCP** – `gcloud auth login --update-adc`

The commands above grant ShadowMap visibility without elevating privileges.

### 2. Build ShadowMap (no coding required)

```bash
git clone https://github.com/YOUR-ORG/ShadowMap.git
cd ShadowMap
cargo build --release
```

This compiles a ready-to-run binary at `./target/release/shadowmap`.

### 3. Run your first scan

```bash
./target/release/shadowmap \
  --domain example.com \
  --providers aws,azure,gcp \
  --report markdown
```

The command above writes a markdown report to the `reports/` folder with confirmed findings and remediation notes.

---

## GPT-4 assisted reporting (optional)

ShadowMap can draft proof-of-concept steps and disclosure-ready summaries when an OpenAI API key is available.

```bash
export OPENAI_API_KEY="sk-..."
./target/release/shadowmap --domain example.com --providers aws,azure,gcp --report markdown --gpt4 --poc
```

You keep full control: review the generated markdown before sharing with engineering or program owners.

---

## Sample finding export

```csv
provider,asset_type,endpoint,risk,validation,gpt4_summary
aws,S3 Bucket,media.example.com,PublicReadEnabled,"ACL: public-read","Marketing assets exposed; see PoC#1"
azure,App Service,api-contoso.azurewebsites.net,DefaultHostnameExposed,"HTTP 200","Default host reachable; enable Front Door"
gcp,Cloud Run,app.run.app,UnauthenticatedInvoke,"IAM allows allUsers","Anonymous invoke open; PoC includes curl command"
```

---

## Roadmap highlights

- Terraform/OpenTofu drift repair suggestions delivered alongside findings.
- Enrichment from SecurityTrails, Shodan, and ASN telemetry for higher-confidence context.
- Native integrations with ticketing platforms to turn findings into tracked work automatically.

---

## Responsible use

ShadowMap is for authorized security testing only. Always secure written approval, respect cloud provider policies, and validate proof-of-concepts in controlled environments.

---

## Contributing & support

Issues and pull requests are welcome—share modules, detection ideas, or doc fixes. ShadowMap exists to help defenders and researchers operate faster, together.

![Alt](https://repobeats.axiom.co/api/embed/09cd32b3e91b58e3094e7592a33604c397c96f40.svg "Repobeats analytics image")
