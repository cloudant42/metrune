use crate::{canonical_model_id, CostKind, UsageMessage};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

const OPENROUTER_MODELS_URL: &str = "https://openrouter.ai/api/v1/models";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ModelPrice {
    pub input_per_million: f64,
    pub output_per_million: f64,
    pub cache_read_per_million: f64,
    pub cache_write_per_million: f64,
    pub reasoning_per_million: f64,
    pub request_per_request: f64,
    pub image_per_image: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PriceAuthority {
    #[serde(rename = "openrouter")]
    OpenRouter,
    #[serde(rename = "official_provider")]
    OfficialProvider,
    #[serde(rename = "organization_override")]
    OrganizationOverride,
    #[serde(rename = "self_hosted")]
    SelfHosted,
    #[serde(rename = "manual")]
    Manual,
}

impl PriceAuthority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenRouter => "openrouter",
            Self::OfficialProvider => "official_provider",
            Self::OrganizationOverride => "organization_override",
            Self::SelfHosted => "self_hosted",
            Self::Manual => "manual",
        }
    }

    fn priority(&self) -> u8 {
        match self {
            Self::Manual => 10,
            Self::OpenRouter => 20,
            Self::OfficialProvider => 30,
            Self::SelfHosted => 40,
            Self::OrganizationOverride => 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PriceEntry {
    pub provider_id: Option<String>,
    pub model_id: String,
    pub price: ModelPrice,
    pub currency: String,
    pub authority: PriceAuthority,
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub retrieved_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub effective_from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub effective_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PriceBook {
    pub version: String,
    pub currency: String,
    pub models: BTreeMap<String, ModelPrice>,
    #[serde(default)]
    pub entries: Vec<PriceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PriceCatalog {
    pub schema_version: String,
    pub catalog_version: String,
    pub generated_at: DateTime<Utc>,
    pub currency: String,
    pub entries: Vec<PriceEntry>,
}

impl PriceCatalog {
    pub const SCHEMA_VERSION: &'static str = "1";

    pub fn load(path: &Path) -> Result<Self> {
        serde_json::from_slice(
            &std::fs::read(path)
                .with_context(|| format!("read price catalog {}", path.display()))?,
        )
        .with_context(|| format!("parse price catalog {}", path.display()))
    }

    pub fn into_pricebook(self) -> PriceBook {
        PriceBook {
            version: self.catalog_version,
            currency: self.currency,
            models: BTreeMap::new(),
            entries: self.entries,
        }
    }

    pub fn from_openrouter_json(body: &str, retrieved_at: DateTime<Utc>) -> Result<Self> {
        let response: OpenRouterModelsResponse =
            serde_json::from_str(body).context("parse OpenRouter model catalog response")?;
        let mut entries = Vec::with_capacity(response.data.len());

        for model in response.data {
            let Some(input_rate) = parse_openrouter_rate(&model.pricing.prompt, &model.id)? else {
                continue;
            };
            let Some(output_rate) = parse_openrouter_rate(&model.pricing.completion, &model.id)?
            else {
                continue;
            };
            let price = ModelPrice {
                input_per_million: input_rate * 1_000_000.0,
                output_per_million: output_rate * 1_000_000.0,
                cache_read_per_million: parse_optional_openrouter_rate(
                    model
                        .pricing
                        .cache_read
                        .as_deref()
                        .or(model.pricing.input_cache_read.as_deref()),
                    &model.id,
                )? * 1_000_000.0,
                cache_write_per_million: parse_optional_openrouter_rate(
                    model
                        .pricing
                        .cache_write
                        .as_deref()
                        .or(model.pricing.input_cache_write.as_deref()),
                    &model.id,
                )? * 1_000_000.0,
                reasoning_per_million: parse_optional_openrouter_rate(
                    model.pricing.internal_reasoning.as_deref(),
                    &model.id,
                )? * 1_000_000.0,
                request_per_request: parse_optional_openrouter_rate(
                    model.pricing.request.as_deref(),
                    &model.id,
                )?,
                image_per_image: parse_optional_openrouter_rate(
                    model.pricing.image.as_deref(),
                    &model.id,
                )?,
            };
            entries.push(PriceEntry {
                provider_id: Some("openrouter".into()),
                model_id: model.id,
                price,
                currency: "USD".into(),
                authority: PriceAuthority::OpenRouter,
                source_url: Some(OPENROUTER_MODELS_URL.into()),
                retrieved_at: Some(retrieved_at),
                effective_from: Some(retrieved_at),
                effective_until: None,
                notes: model
                    .canonical_slug
                    .map(|slug| format!("canonical slug: {slug}")),
            });
        }

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.into(),
            catalog_version: format!("openrouter-{}", retrieved_at.format("%Y%m%dT%H%M%SZ")),
            generated_at: retrieved_at,
            currency: "USD".into(),
            entries,
        })
    }
}

impl PriceBook {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read pricebook or catalog {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse pricing JSON {}", path.display()))?;
        if value.get("catalogVersion").is_some() || value.get("schemaVersion").is_some() {
            return serde_json::from_value::<PriceCatalog>(value)
                .map(PriceCatalog::into_pricebook)
                .with_context(|| format!("parse price catalog {}", path.display()));
        }
        serde_json::from_value(value).with_context(|| format!("parse pricebook {}", path.display()))
    }

    pub fn estimate(&self, message: &mut UsageMessage) -> bool {
        if message.cost.kind == CostKind::Reported {
            return false;
        }
        let canonical = canonical_model_id(&message.model_id);
        let provider = message.provider_id.to_ascii_lowercase();
        let now = Utc::now();
        let selected = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let entry_model = canonical_model_id(&entry.model_id);
                if entry_model != canonical
                    || entry
                        .provider_id
                        .as_ref()
                        .is_some_and(|id| id.to_ascii_lowercase() != provider)
                    || entry.effective_from.is_some_and(|date| date > now)
                    || entry.effective_until.is_some_and(|date| date <= now)
                {
                    return None;
                }
                let provider_specific = entry.provider_id.is_some() as u8;
                let effective_timestamp = entry
                    .effective_from
                    .map(|date| date.timestamp())
                    .unwrap_or(i64::MIN);
                Some((
                    index,
                    entry,
                    (
                        provider_specific,
                        entry.authority.priority(),
                        effective_timestamp,
                        index,
                    ),
                ))
            })
            .max_by_key(|(_, _, rank)| *rank)
            .map(|(_, entry, _)| {
                (
                    entry.price.clone(),
                    entry.currency.clone(),
                    entry.authority.as_str(),
                )
            });

        let (price, currency, authority) = if let Some(selected) = selected {
            selected
        } else {
            let key = format!("{provider}/{canonical}");
            let Some(price) = self
                .models
                .get(&key)
                .or_else(|| self.models.get(&canonical))
            else {
                return false;
            };
            (price.clone(), self.currency.clone(), "manual")
        };

        let million = 1_000_000.0;
        message.cost.amount = (message.tokens.input as f64 * price.input_per_million
            + message.tokens.output as f64 * price.output_per_million
            + message.tokens.cache_read as f64 * price.cache_read_per_million
            + message.tokens.cache_write as f64 * price.cache_write_per_million
            + message.tokens.reasoning as f64 * price.reasoning_per_million)
            / million;
        message.cost.currency = if currency.is_empty() {
            if self.currency.is_empty() {
                "USD".into()
            } else {
                self.currency.clone()
            }
        } else {
            currency
        };
        message.cost.kind = CostKind::Estimated;
        message.cost.pricebook_version = Some(self.version.clone());
        message.cost.price_source = Some(authority.into());
        true
    }
}

#[derive(Debug, Deserialize)]
struct OpenRouterModelsResponse {
    data: Vec<OpenRouterModel>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterModel {
    id: String,
    #[serde(default)]
    canonical_slug: Option<String>,
    pricing: OpenRouterPricing,
}

#[derive(Debug, Deserialize)]
struct OpenRouterPricing {
    prompt: String,
    completion: String,
    #[serde(default)]
    cache_read: Option<String>,
    #[serde(default)]
    cache_write: Option<String>,
    #[serde(default)]
    input_cache_read: Option<String>,
    #[serde(default)]
    input_cache_write: Option<String>,
    #[serde(default)]
    internal_reasoning: Option<String>,
    #[serde(default)]
    request: Option<String>,
    #[serde(default)]
    image: Option<String>,
}

fn parse_optional_openrouter_rate(value: Option<&str>, model_id: &str) -> Result<f64> {
    value
        .map(|rate| parse_openrouter_rate(rate, model_id))
        .transpose()
        .map(|rate| rate.flatten().unwrap_or_default())
}

fn parse_openrouter_rate(value: &str, model_id: &str) -> Result<Option<f64>> {
    let rate = value
        .parse::<f64>()
        .with_context(|| format!("parse OpenRouter price {value:?} for model {model_id}"))?;
    if rate == -1.0 {
        // OpenRouter uses -1 for a price that is not available for this model.
        return Ok(None);
    }
    if !rate.is_finite() || rate < 0.0 {
        bail!(
            "OpenRouter price {value:?} for model {model_id} is not a finite non-negative number"
        );
    }
    Ok(Some(rate))
}
