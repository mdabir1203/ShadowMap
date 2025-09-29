use std::collections::HashMap;
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use trust_dns_resolver::TokioAsyncResolver;

use crate::constants::{CLOUD_SAAS_PATTERNS, DNS_TIMEOUT};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudAssetStatus {
    Accessible,
    Forbidden,
    ExistsNoAccess,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudAssetFinding {
    pub provider: String,
    pub asset: String,
    pub status: CloudAssetStatus,
    pub notes: Option<String>,
}

impl CloudAssetStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudAssetStatus::Accessible => "accessible",
            CloudAssetStatus::Forbidden => "forbidden",
            CloudAssetStatus::ExistsNoAccess => "exists_no_access",
            CloudAssetStatus::Unknown => "unknown",
        }
    }
}

impl CloudAssetFinding {
    pub fn status_string(&self) -> &'static str {
        self.status.as_str()
    }
}

pub async fn cloud_saas_recon(
    subs: &std::collections::HashSet<String>,
    resolver: TokioAsyncResolver,
    max_concurrency: usize,
) -> HashMap<String, Vec<String>> {
    let resolver = Arc::new(resolver);
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut tasks = FuturesUnordered::new();

    for sub in subs.iter() {
        let sub_clone = sub.clone();
        let resolver_clone = Arc::clone(&resolver);
        let semaphore_clone = Arc::clone(&semaphore);

        tasks.push(tokio::spawn(async move {
            let _permit = semaphore_clone
                .acquire()
                .await
                .expect("Semaphore unexpectedly closed");

            let mut findings: Vec<String> = Vec::new();

            for (provider, pattern) in CLOUD_SAAS_PATTERNS.iter() {
                if pattern.is_match(&sub_clone) {
                    findings.push(format!("Matched provider pattern: {}", provider));
                }
            }

            let predicted_candidates = vec![
                format!("api.{}", sub_clone),
                format!("dev.{}", sub_clone),
                format!("staging.{}", sub_clone),
                format!("{}.s3.amazonaws.com", sub_clone),
                format!("{}.blob.core.windows.net", sub_clone),
                format!("{}.storage.googleapis.com", sub_clone),
            ];

            for cand in predicted_candidates {
                match timeout(DNS_TIMEOUT, resolver_clone.lookup_ip(cand.clone())).await {
                    Ok(Ok(lookup)) if lookup.iter().next().is_some() => {
                        findings.push(format!("Predicted exists: {}", cand));
                    }
                    _ => {}
                }
            }

            if !findings.is_empty() {
                Some((sub_clone, findings))
            } else {
                None
            }
        }));
    }

    let mut results = HashMap::new();
    while let Some(res) = tasks.next().await {
        if let Ok(Some((sub_clone, findings))) = res {
            results.insert(sub_clone, findings);
        }
    }

    results
}

pub async fn deep_cloud_asset_discovery(
    subs: &std::collections::HashSet<String>,
    client: &Client,
    max_concurrency: usize,
    per_asset_timeout: Duration,
) -> HashMap<String, Vec<CloudAssetFinding>> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut tasks = FuturesUnordered::new();

    for sub in subs.iter() {
        let sub = sub.clone();
        let semaphore = Arc::clone(&semaphore);
        let client = client.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = semaphore
                .acquire()
                .await
                .expect("Semaphore unexpectedly closed");

            let mut findings = Vec::new();
            let candidates = candidate_cloud_assets(&sub);

            for (provider, asset) in candidates {
                let request = client.head(&asset);
                match timeout(per_asset_timeout, request.send()).await {
                    Ok(Ok(resp)) => {
                        let status = resp.status();
                        let (finding_status, notes) = match status.as_u16() {
                            200..=299 => (
                                CloudAssetStatus::Accessible,
                                Some(format!("HTTP {}", status)),
                            ),
                            401 | 402 | 403 => (
                                CloudAssetStatus::ExistsNoAccess,
                                Some(format!("Restricted access ({})", status)),
                            ),
                            404 => continue,
                            429 => (
                                CloudAssetStatus::Forbidden,
                                Some("Rate limited when probing asset".to_string()),
                            ),
                            _ => (
                                CloudAssetStatus::Unknown,
                                Some(format!("Unexpected status {}", status)),
                            ),
                        };

                        if !matches!(finding_status, CloudAssetStatus::Unknown) {
                            findings.push(CloudAssetFinding {
                                provider: provider.clone(),
                                asset,
                                status: finding_status,
                                notes: notes.clone(),
                            });
                        }
                    }
                    Ok(Err(err)) => {
                        let message = err.to_string();
                        if message.contains("dns") || message.contains("No such host") {
                            continue;
                        }
                        findings.push(CloudAssetFinding {
                            provider: provider.clone(),
                            asset,
                            status: CloudAssetStatus::Unknown,
                            notes: Some(message),
                        });
                    }
                    Err(_) => {
                        findings.push(CloudAssetFinding {
                            provider: provider.clone(),
                            asset,
                            status: CloudAssetStatus::Unknown,
                            notes: Some("Timed out probing asset".to_string()),
                        });
                    }
                }
            }

            if findings.is_empty() {
                None
            } else {
                Some((sub, findings))
            }
        }));
    }

    let mut results = HashMap::new();
    while let Some(res) = tasks.next().await {
        if let Ok(Some((sub, findings))) = res {
            results.insert(sub, findings);
        }
    }

    results
}

fn candidate_cloud_assets(sub: &str) -> Vec<(String, String)> {
    let dashed = sub.replace('.', "-");

    vec![
        (
            "aws_s3".to_string(),
            format!("https://{}.s3.amazonaws.com", sub),
        ),
        (
            "aws_s3".to_string(),
            format!("https://{}.s3.amazonaws.com", dashed),
        ),
        (
            "aws_cloudfront".to_string(),
            format!("https://{}.cloudfront.net", dashed),
        ),
        (
            "azure_blob".to_string(),
            format!("https://{}.blob.core.windows.net", sub),
        ),
        (
            "azure_static_web".to_string(),
            format!("https://{}.azurestaticapps.net", dashed),
        ),
        (
            "gcp_storage".to_string(),
            format!("https://{}.storage.googleapis.com", sub),
        ),
        (
            "gcp_storage".to_string(),
            format!("https://storage.googleapis.com/{}", sub),
        ),
        (
            "digitalocean_spaces".to_string(),
            format!("https://{}.digitaloceanspaces.com", sub),
        ),
        (
            "cloudflare_r2".to_string(),
            format!("https://{}.r2.cloudflarestorage.com", sub),
        ),
        (
            "wasabi".to_string(),
            format!("https://{}.wasabisys.com", sub),
        ),
    ]
}
