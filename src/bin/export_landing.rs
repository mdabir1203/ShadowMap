use std::fs;
use std::path::Path;

use anyhow::Result;
use shadowmap::web::{render_landing_page, LandingPageContext, PricingPlan};

fn main() -> Result<()> {
    let context = LandingPageContext {
        publishable_key: None,
        plans: vec![
            PricingPlan {
                id: "starter",
                name: "Starter",
                summary: "Launch automation-grade recon for boutique agencies and red teams.",
                ideal_for: "Solo operators",
                highlight: false,
                usd_cents: 7900,
                eur_cents: 7500,
                features: &[
                    "Unlimited on-demand reconnaissance jobs",
                    "Live subdomain, DNS, and takeover detection",
                    "Automated PDF & JSON reporting exports",
                    "Email support with 1-business-day SLA",
                ],
                checkout_ready_us: false,
                checkout_ready_eu: false,
            },
            PricingPlan {
                id: "growth",
                name: "Growth",
                summary: "Scale your practice with team workspaces, automations, and real-time monitoring.",
                ideal_for: "Agencies & MSSPs",
                highlight: true,
                usd_cents: 15900,
                eur_cents: 14900,
                features: &[
                    "Everything in Starter plus scheduled monitoring",
                    "Team workspaces with role-based access control",
                    "Slack and webhook alerting for high-risk findings",
                    "Dedicated success engineer and quarterly playbooks",
                ],
                checkout_ready_us: false,
                checkout_ready_eu: false,
            },
            PricingPlan {
                id: "enterprise",
                name: "Enterprise",
                summary: "For global security organizations that need private deployments and custom workflows.",
                ideal_for: "Global teams",
                highlight: false,
                usd_cents: 34900,
                eur_cents: 32900,
                features: &[
                    "Private cloud or on-premise deployment options",
                    "Custom modules and API surface for internal tooling",
                    "Advanced compliance reporting & SOC2 documentation",
                    "24/7 incident response with named TAM",
                ],
                checkout_ready_us: false,
                checkout_ready_eu: false,
            },
        ],
    };

    let html = render_landing_page(&context);
    let output_dir = Path::new("landing-page");
    fs::create_dir_all(output_dir)?;
    fs::write(output_dir.join("index.html"), html)?;
    println!("Wrote {}", output_dir.join("index.html").display());

    Ok(())
}
