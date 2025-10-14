use chrono::DateTime;
use chrono::Utc;
use v_htmlescape::escape;

#[derive(Clone, Debug)]
pub struct PricingPlan {
    pub id: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub ideal_for: &'static str,
    pub highlight: bool,
    pub usd_cents: u32,
    pub eur_cents: u32,
    pub features: &'static [&'static str],
    pub checkout_ready_us: bool,
    pub checkout_ready_eu: bool,
}

#[derive(Clone, Debug)]
pub struct LandingPageContext {
    pub publishable_key: Option<String>,
    pub plans: Vec<PricingPlan>,
}

pub fn render_landing_page(context: &LandingPageContext) -> String {
    fn format_money(amount_cents: u32, currency: &str) -> String {
        let major = amount_cents / 100;
        let minor = amount_cents % 100;
        if minor == 0 {
            format!("{}{}", currency, major)
        } else {
            format!("{}{}.{:02}", currency, major, minor)
        }
    }

    let mut plan_cards = String::new();
    for plan in &context.plans {
        let mut feature_list = String::new();
        for feature in plan.features {
            feature_list.push_str(&format!(
                "<li>\n                        <span class=\"feature-icon\">✓</span>\n                        <span>{}</span>\n                    </li>",
                escape(feature)
            ));
        }

        let us_price = format_money(plan.usd_cents, "$ ");
        let eu_price = format_money(plan.eur_cents, "€ ");
        let highlight_class = if plan.highlight {
            " plan-card--highlight"
        } else {
            ""
        };
        let badge = if plan.highlight {
            "<span class=\"plan-badge\">Most popular</span>"
        } else {
            ""
        };
        let cta_state = if plan.checkout_ready_us || plan.checkout_ready_eu {
            ""
        } else {
            " data-disabled-copy=\"Email us to activate payments\""
        };

        plan_cards.push_str(&format!(
            r#"            <article class="plan-card{highlight_class}" data-plan-card data-plan-id="{id}" data-us-available="{us}" data-eu-available="{eu}">
                    {badge}
                    <header>
                        <div class="plan-title-row">
                            <h3>{name}</h3>
                            <span class="plan-ideal">{ideal}</span>
                        </div>
                        <p>{summary}</p>
                    </header>
                    <div class="plan-price" data-plan-price data-us-price="{us_price}" data-eu-price="{eu_price}">
                        <span class="price-amount"></span>
                        <span class="price-frequency">/month</span>
                    </div>
                    <ul class="plan-features">
                        {features}
                    </ul>
                    <button class="plan-cta" data-plan-cta data-plan-id="{id}"{cta_state}>Start free trial</button>
                </article>
"#,
            highlight_class = highlight_class,
            id = escape(plan.id),
            name = escape(plan.name),
            summary = escape(plan.summary),
            ideal = escape(plan.ideal_for),
            us = if plan.checkout_ready_us { "true" } else { "false" },
            eu = if plan.checkout_ready_eu { "true" } else { "false" },
            us_price = escape(&us_price),
            eu_price = escape(&eu_price),
            features = feature_list,
            cta_state = cta_state,
            badge = badge,
        ));
    }

    let publishable_key = context
        .publishable_key
        .as_ref()
        .map(|key| escape(key))
        .unwrap_or_else(|| escape(""));

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ShadowMap – Precision Reconnaissance Without the Busywork</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://js.stripe.com/v3/"></script>
    <style>
        :root {{
            color-scheme: dark;
            --bg: #010617;
            --card: rgba(15, 23, 42, 0.7);
            --accent: #38bdf8;
            --text: #e2e8f0;
            --subtle: #94a3b8;
            --muted: #64748b;
            --border: rgba(148, 163, 184, 0.15);
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: radial-gradient(circle at top, #0b1224, var(--bg) 60%);
            color: var(--text);
        }}
        .page {{
            width: min(1080px, 95vw);
            margin: 0 auto;
            padding: 3.5rem 0 4rem;
        }}
        header.hero {{
            text-align: center;
            padding: 4rem 0 2.5rem;
        }}
        .hero h1 {{
            font-size: clamp(2.4rem, 5vw, 3.4rem);
            margin: 0;
            letter-spacing: -0.03em;
        }}
        .hero p {{
            margin: 1.2rem auto 2rem;
            max-width: 640px;
            color: var(--subtle);
            font-size: 1.1rem;
        }}
        .eyebrow {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.4rem 0.9rem;
            border-radius: 999px;
            background: rgba(56, 189, 248, 0.12);
            color: var(--accent);
            font-weight: 600;
            font-size: 0.8rem;
            letter-spacing: 0.14em;
            text-transform: uppercase;
        }}
        .hero-cta {{
            display: inline-flex;
            gap: 0.75rem;
            align-items: center;
            padding: 0.95rem 1.85rem;
            border-radius: 999px;
            border: none;
            font-size: 1rem;
            font-weight: 600;
            background: linear-gradient(135deg, #38bdf8, #2563eb);
            color: #0f172a;
            cursor: pointer;
            box-shadow: 0 22px 40px rgba(37, 99, 235, 0.35);
            text-decoration: none;
        }}
        .stats-grid {{
            margin-top: 3rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1.5rem;
        }}
        .stat {{
            padding: 1.6rem 1.8rem;
            border-radius: 1.25rem;
            background: var(--card);
            border: 1px solid var(--border);
            backdrop-filter: blur(18px);
        }}
        .stat h3 {{
            margin: 0;
            font-size: 2rem;
        }}
        .stat p {{
            margin: 0.55rem 0 0;
            color: var(--subtle);
        }}
        section {{
            margin-top: 4.5rem;
        }}
        .section-heading {{
            font-size: clamp(1.9rem, 3vw, 2.4rem);
            margin-bottom: 1rem;
        }}
        .feature-grid {{
            display: grid;
            gap: 1.8rem;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        }}
        .feature-card {{
            padding: 1.8rem;
            border-radius: 1.25rem;
            background: var(--card);
            border: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
        }}
        .feature-card h3 {{
            margin: 0;
            font-size: 1.2rem;
        }}
        .feature-card p {{
            margin: 0;
            color: var(--subtle);
        }}
        .pricing-header {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
        }}
        .region-toggle {{
            background: var(--card);
            border-radius: 999px;
            border: 1px solid var(--border);
            padding: 0.35rem;
            display: inline-flex;
            gap: 0.35rem;
        }}
        .region-toggle button {{
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 999px;
            background: transparent;
            color: var(--subtle);
            font-weight: 600;
            cursor: pointer;
        }}
        .region-toggle button[data-active="true"] {{
            background: rgba(56, 189, 248, 0.15);
            color: var(--text);
        }}
        .plan-grid {{
            margin-top: 2.5rem;
            display: grid;
            gap: 1.5rem;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        }}
        .plan-card {{
            background: var(--card);
            border-radius: 1.4rem;
            border: 1px solid var(--border);
            padding: 2rem 1.9rem;
            display: flex;
            flex-direction: column;
            gap: 1.6rem;
            position: relative;
        }}
        .plan-badge {{
            position: absolute;
            top: 1.5rem;
            right: 1.5rem;
            background: rgba(56, 189, 248, 0.18);
            color: var(--accent);
            font-weight: 700;
            font-size: 0.72rem;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            padding: 0.35rem 0.8rem;
            border-radius: 999px;
        }}
        .plan-card--highlight {{
            border-color: rgba(56, 189, 248, 0.45);
            box-shadow: 0 30px 50px rgba(56, 189, 248, 0.15);
        }}
        .plan-title-row {{
            display: flex;
            align-items: baseline;
            justify-content: space-between;
            gap: 0.75rem;
        }}
        .plan-title-row h3 {{
            margin: 0;
            font-size: 1.35rem;
        }}
        .plan-ideal {{
            font-size: 0.85rem;
            color: var(--accent);
            font-weight: 600;
        }}
        .plan-card p {{
            margin: 0;
            color: var(--subtle);
        }}
        .plan-price {{
            display: flex;
            align-items: baseline;
            gap: 0.45rem;
            font-size: 2.4rem;
            font-weight: 700;
        }}
        .plan-price .price-frequency {{
            font-size: 0.95rem;
            color: var(--subtle);
            font-weight: 500;
        }}
        .plan-features {{
            list-style: none;
            margin: 0;
            padding: 0;
            display: grid;
            gap: 0.75rem;
        }}
        .plan-features li {{
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 0.75rem;
            align-items: start;
            color: var(--subtle);
        }}
        .feature-icon {{
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: grid;
            place-items: center;
            background: rgba(56, 189, 248, 0.18);
            color: var(--accent);
            font-weight: 700;
            font-size: 0.85rem;
        }}
        .plan-cta {{
            border: none;
            border-radius: 999px;
            padding: 0.85rem 1.5rem;
            font-weight: 600;
            background: linear-gradient(135deg, #38bdf8, #2563eb);
            color: #0f172a;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        .plan-cta:hover {{
            transform: translateY(-1px);
            box-shadow: 0 18px 38px rgba(37, 99, 235, 0.35);
        }}
        .plan-cta[disabled] {{
            background: rgba(148, 163, 184, 0.3);
            color: var(--muted);
            cursor: not-allowed;
            box-shadow: none;
        }}
        .checkout-panel {{
            margin-top: 2rem;
            padding: 1.5rem 1.75rem;
            background: rgba(15, 23, 42, 0.55);
            border: 1px solid var(--border);
            border-radius: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}
        .checkout-panel label {{
            display: flex;
            flex-direction: column;
            gap: 0.45rem;
            color: var(--subtle);
            font-size: 0.95rem;
        }}
        .checkout-panel input {{
            border-radius: 0.85rem;
            border: 1px solid var(--border);
            padding: 0.75rem 0.9rem;
            background: rgba(15, 23, 42, 0.6);
            color: var(--text);
        }}
        .checkout-panel small {{
            color: var(--muted);
        }}
        .status-line {{
            min-height: 1.2rem;
            font-size: 0.9rem;
            color: var(--accent);
        }}
        footer {{
            margin-top: 5rem;
            padding: 3rem 0 1.5rem;
            color: var(--muted);
            text-align: center;
            font-size: 0.9rem;
        }}
        a.inline-link {{
            color: var(--accent);
            text-decoration: none;
            font-weight: 600;
        }}
        a.inline-link:hover {{
            text-decoration: underline;
        }}
        @media (max-width: 720px) {{
            header.hero {{
                padding-top: 3rem;
            }}
            .hero-cta {{
                width: 100%;
                justify-content: center;
            }}
            .plan-card {{
                padding: 1.6rem;
            }}
        }}
    </style>
</head>
<body data-stripe-key="{publishable_key}">
    <div class="page">
        <header class="hero">
            <p class="eyebrow">ShadowMap Recon Platform</p>
            <h1>Land more clients with enterprise-grade recon in minutes.</h1>
            <p>Feed ShadowMap a target domain and receive a prioritized report covering subdomains, misconfigurations, cloud assets, and takeover risks. Built by operators for revenue teams who need answers fast.</p>
            <a class="hero-cta" href="#pricing">View pricing</a>
        </header>

        <section class="stats-grid">
            <div class="stat">
                <h3>14x</h3>
                <p>Faster than manual reconnaissance workflows.</p>
            </div>
            <div class="stat">
                <h3>92%</h3>
                <p>Of beta customers closed new business within 30 days.</p>
            </div>
            <div class="stat">
                <h3>4.9/5</h3>
                <p>Average rating from security teams across the US & EU.</p>
            </div>
        </section>

        <section>
            <h2 class="section-heading">Why fast-moving teams choose ShadowMap</h2>
            <div class="feature-grid">
                <article class="feature-card">
                    <h3>Agentic reconnaissance</h3>
                    <p>Autonomous workflows pair our curated fingerprint database with graph intelligence to surface exploitable insight automatically.</p>
                </article>
                <article class="feature-card">
                    <h3>Enterprise ready</h3>
                    <p>Privacy-first architecture, EU data residency options, and SOC2-aligned controls keep compliance teams comfortable.</p>
                </article>
                <article class="feature-card">
                    <h3>Sales enablement focus</h3>
                    <p>Actionable narratives, not raw logs—our reports plug straight into proposals and client portals.</p>
                </article>
            </div>
        </section>

        <section id="pricing">
            <div class="pricing-header">
                <div>
                    <h2 class="section-heading">Transparent pricing for US & EU teams</h2>
                    <p style="color: var(--subtle); max-width: 520px;">Choose your operating region to see localized pricing. Every plan includes unlimited workspaces, automated monitoring, and concierge onboarding.</p>
                </div>
                <div class="region-toggle" data-region-toggle>
                    <button type="button" data-region="us" data-active="true">USA USD</button>
                    <button type="button" data-region="eu" data-active="false">EU EUR</button>
                </div>
            </div>
            <div class="plan-grid">
{plan_cards}            </div>

            <div class="checkout-panel">
                <label>
                    Work email (optional)
                    <input type="email" placeholder="you@company.com" data-email-input>
                </label>
                <small>We'll pre-fill your receipt with this email.</small>
                <div class="status-line" data-checkout-status></div>
                <small>Prefer an invoice or custom deployment? <a class="inline-link" href="mailto:hello@shadowmap.io">Contact our team</a>.</small>
            </div>
        </section>

        <section>
            <h2 class="section-heading">Frequently asked</h2>
            <div class="feature-grid">
                <article class="feature-card">
                    <h3>Can we self-host ShadowMap?</h3>
                    <p>Growth and Enterprise plans support private cloud deployments with automated updates and optional managed services.</p>
                </article>
                <article class="feature-card">
                    <h3>Do you support procurement in the EU?</h3>
                    <p>Yes—pricing is VAT-ready and we issue localized invoices through Stripe. Need a DPA? We provide one-click execution.</p>
                </article>
                <article class="feature-card">
                    <h3>What does onboarding look like?</h3>
                    <p>You'll get a dedicated security engineer, custom playbooks, and Slack-based support within one business day of signing up.</p>
                </article>
            </div>
        </section>

        <footer>
            Built by the ShadowMap team. Ready for lift-off? <a class="inline-link" href="#pricing">Choose your plan</a> or <a class="inline-link" href="/app">launch the dashboard</a>.
        </footer>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {{
            const body = document.body;
            const publishableKey = body.dataset.stripeKey;
            const stripe = publishableKey ? Stripe(publishableKey) : null;
            const regionButtons = document.querySelectorAll('[data-region-toggle] [data-region]');
            const planPrices = document.querySelectorAll('[data-plan-price]');
            const planButtons = document.querySelectorAll('[data-plan-cta]');
            const statusLine = document.querySelector('[data-checkout-status]');
            const emailInput = document.querySelector('[data-email-input]');
            let activeRegion = 'us';

            function updateRegionButtons() {{
                regionButtons.forEach(button => {{
                    const isActive = button.dataset.region === activeRegion;
                    button.dataset.active = isActive ? 'true' : 'false';
                }});
            }}

            function updatePlanCards() {{
                planPrices.forEach(node => {{
                    const price = node.dataset[activeRegion + 'Price'];
                    if (price) {{
                        const amount = node.querySelector('.price-amount');
                        if (amount) {{
                            amount.textContent = price;
                        }}
                    }}
                }});

                planButtons.forEach(button => {{
                    const planCard = document.querySelector(`[data-plan-card][data-plan-id="${{button.dataset.planId}}"]`);
                    if (!planCard) {{
                        return;
                    }}
                    const available = planCard.dataset[activeRegion + 'Available'] === 'true';
                    if (!stripe || !available) {{
                        button.disabled = true;
                        const disabledCopy = button.dataset.disabledCopy;
                        button.textContent = disabledCopy || 'Talk to sales';
                    }} else {{
                        button.disabled = false;
                        button.textContent = 'Start free trial';
                    }}
                }});
            }}

            regionButtons.forEach(button => {{
                button.addEventListener('click', () => {{
                    activeRegion = button.dataset.region;
                    updateRegionButtons();
                    updatePlanCards();
                }});
            }});

            planButtons.forEach(button => {{
                button.addEventListener('click', async () => {{
                    if (!stripe) {{
                        statusLine.textContent = 'Payments are not configured yet. Email hello@shadowmap.io and we will get you set up.';
                        return;
                    }}
                    const planId = button.dataset.planId;
                    const payload = {{
                        plan_id: planId,
                        region: activeRegion,
                        email: emailInput && emailInput.value ? emailInput.value : undefined,
                    }};
                    button.disabled = true;
                    button.textContent = 'Redirecting...';
                    statusLine.textContent = '';
                    try {{
                        const response = await fetch('/create-checkout-session', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify(payload),
                        }});
                        if (!response.ok) {{
                            const errorText = await response.text();
                            throw new Error(errorText || 'Unable to start checkout');
                        }}
                        const data = await response.json();
                        if (data.session_id) {{
                            const result = await stripe.redirectToCheckout({{ sessionId: data.session_id }});
                            if (result.error) {{
                                throw result.error;
                            }}
                        }} else {{
                            throw new Error('Invalid response from payment processor.');
                        }}
                    }} catch (err) {{
                        console.error(err);
                        statusLine.textContent = err.message || 'We were unable to start the checkout session. Please try again or email hello@shadowmap.io.';
                        button.disabled = false;
                        button.textContent = 'Start free trial';
                    }}
                }});
            }});

            updateRegionButtons();
            updatePlanCards();
        }});
    </script>
</body>
</html>
"##,
        plan_cards = plan_cards,
        publishable_key = publishable_key,
    )
}

use super::state::{Job, JobConfig, JobStatus};

pub fn render_index_page(jobs: &[Job]) -> String {
    let defaults = JobConfig::default();
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ShadowMap Recon Dashboard</title>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    <style>
        :root {{
            color-scheme: dark;
        }}
        body {{
            margin: 0;
            font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: radial-gradient(circle at top, #0f172a, #020617 60%);
            color: #e2e8f0;
        }}
        main {{
            width: min(960px, 94vw);
            margin: 3rem auto;
            background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(18px);
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-radius: 18px;
            padding: 2.5rem 2.75rem;
            box-shadow: 0 40px 70px rgba(15, 23, 42, 0.45);
        }}
        header h1 {{
            margin: 0;
            font-size: clamp(1.8rem, 3vw, 2.4rem);
            font-weight: 600;
        }}
        header p {{
            margin: 0.35rem 0 0;
            color: #94a3b8;
        }}
        form {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1.5rem;
            margin-top: 2rem;
            align-items: end;
        }}
        label {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            font-size: 0.95rem;
            color: #cbd5f5;
            letter-spacing: 0.01em;
        }}
        input[type="text"],
        input[type="number"] {{
            border-radius: 12px;
            border: 1px solid rgba(148, 163, 184, 0.3);
            background: rgba(15, 23, 42, 0.6);
            color: #e2e8f0;
            padding: 0.75rem 0.9rem;
            font-size: 1rem;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }}
        input:focus {{
            outline: none;
            border-color: #38bdf8;
            box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.15);
        }}
        button {{
            border-radius: 12px;
            border: none;
            padding: 0.85rem 1.6rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            background: linear-gradient(135deg, #38bdf8, #2563eb);
            color: #0f172a;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        button:hover {{
            transform: translateY(-1px);
            box-shadow: 0 18px 30px rgba(56, 189, 248, 0.35);
        }}
        section {{
            margin-top: 2.5rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1.25rem;
        }}
        thead th {{
            text-align: left;
            font-size: 0.9rem;
            font-weight: 600;
            color: #94a3b8;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            padding: 0.75rem 1rem;
        }}
        tbody td {{
            padding: 0.9rem 1rem;
            border-top: 1px solid rgba(148, 163, 184, 0.12);
            vertical-align: top;
        }}
        tbody tr:hover {{
            background: rgba(56, 189, 248, 0.07);
        }}
        .status {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.3rem 0.9rem;
            border-radius: 999px;
            font-size: 0.85rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
        }}
        .status::before {{
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }}
        .status-Queued {{
            background: rgba(251, 191, 36, 0.15);
            color: #fbbf24;
        }}
        .status-Queued::before {{
            background: #fbbf24;
        }}
        .status-Running {{
            background: rgba(96, 165, 250, 0.18);
            color: #60a5fa;
        }}
        .status-Running::before {{
            background: #38bdf8;
        }}
        .status-Completed {{
            background: rgba(134, 239, 172, 0.2);
            color: #86efac;
        }}
        .status-Completed::before {{
            background: #4ade80;
        }}
        .status-Failed {{
            background: rgba(248, 113, 113, 0.2);
            color: #f87171;
        }}
        .status-Failed::before {{
            background: #f87171;
        }}
        .job-actions a {{
            color: #38bdf8;
            text-decoration: none;
            font-weight: 600;
        }}
        .job-actions a:hover {{
            text-decoration: underline;
        }}
        .status-note {{
            margin-top: 0.45rem;
            font-size: 0.85rem;
            color: rgba(248, 113, 113, 0.9);
        }}
        .config-pill {{
            display: inline-flex;
            gap: 0.4rem;
            align-items: center;
            padding: 0.3rem 0.75rem;
            border-radius: 999px;
            background: rgba(148, 163, 184, 0.15);
            color: #cbd5f5;
            font-size: 0.85rem;
        }}
        .table-empty {{
            padding: 2.5rem 1rem;
            text-align: center;
            color: #64748b;
            font-size: 0.95rem;
        }}
    </style>
</head>
<body>
<main>
    <header>
        <h1>ShadowMap Recon Dashboard</h1>
        <p>Launch reconnaissance jobs, monitor progress, and retrieve structured reports in seconds.</p>
    </header>
    <form hx-post="/jobs" hx-target="#jobs-body" hx-swap="afterbegin">
        <label>
            Domain
            <input type="text" name="domain" required placeholder="example.com" autocomplete="off">
        </label>
        <label>
            Concurrency
            <input type="number" name="concurrency" min="1" max="500" value="{concurrency}">
        </label>
        <label>
            Timeout (s)
            <input type="number" name="timeout" min="1" max="120" value="{timeout}">
        </label>
        <label>
            Retries
            <input type="number" name="retries" min="0" max="10" value="{retries}">
        </label>
        <button type="submit">Launch recon</button>
    </form>
    <section>
        <h2>Recent jobs</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Last update</th>
                    <th>Config</th>
                    <th>Output</th>
                </tr>
            </thead>
            <tbody id="jobs-body"
                   hx-get="/jobs"
                   hx-trigger="load, every 5s"
                   hx-target="#jobs-body"
                   hx-swap="innerHTML">
                {rows}
            </tbody>
        </table>
    </section>
</main>
</body>
</html>"##,
        concurrency = defaults.concurrency,
        timeout = defaults.timeout,
        retries = defaults.retries,
        rows = if jobs.is_empty() {
            String::from(
                r#"<tr><td colspan="5" class="table-empty">No jobs yet. Launch a scan to populate the dashboard.</td></tr>"#,
            )
        } else {
            render_job_rows(jobs)
        },
    )
}

pub fn render_job_rows(jobs: &[Job]) -> String {
    jobs.iter().map(render_job_row).collect()
}

pub fn render_job_row(job: &Job) -> String {
    let domain = escape(&job.domain);
    let status_class = match job.status {
        JobStatus::Queued => "Queued",
        JobStatus::Running => "Running",
        JobStatus::Completed => "Completed",
        JobStatus::Failed => "Failed",
    };
    let status_label = match job.status {
        JobStatus::Queued => "Queued",
        JobStatus::Running => "Running",
        JobStatus::Completed => "Completed",
        JobStatus::Failed => "Failed",
    };
    let updated = humanize_timestamp(job.updated_at);
    let config = format!(
        r#"<span class="config-pill"><strong>{}</strong> workers • {}s timeout • {} retries</span>"#,
        job.config.concurrency, job.config.timeout, job.config.retries
    );
    let output = match (&job.status, &job.output_path) {
        (JobStatus::Completed, Some(_)) => format!(
            r#"<div class="job-actions"><a href="/jobs/{id}/report" hx-boost="false" target="_blank">Download JSON</a></div>"#,
            id = job.id
        ),
        _ => String::from(r#"<span style="color:#475569;">Pending</span>"#),
    };
    let note = match (&job.status, &job.error) {
        (JobStatus::Failed, Some(err)) => {
            format!(r#"<div class="status-note">{}</div>"#, escape(err))
        }
        _ => String::new(),
    };

    format!(
        r#"<tr id="job-{id}"><td>{domain}</td><td><span class="status status-{class}">{label}</span>{note}</td><td>{updated}</td><td>{config}</td><td>{output}</td></tr>"#,
        id = job.id,
        domain = domain,
        class = status_class,
        label = status_label,
        updated = escape(&updated),
        config = config,
        output = output,
        note = note,
    )
}

fn humanize_timestamp(ts: DateTime<Utc>) -> String {
    ts.with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}
