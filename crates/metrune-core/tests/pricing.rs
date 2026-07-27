use chrono::Utc;
use metrune_core::{
    pricing::{ModelPrice, PriceAuthority, PriceBook, PriceCatalog, PriceEntry},
    Cost, TokenBreakdown, UsageMessage,
};
use std::collections::BTreeMap;

#[test]
fn estimates_unknown_cost_with_versioned_custom_pricebook() {
    let mut models = BTreeMap::new();
    models.insert(
        "openai/gpt-5".into(),
        ModelPrice {
            input_per_million: 2.0,
            output_per_million: 8.0,
            ..ModelPrice::default()
        },
    );
    let book = PriceBook {
        version: "contract-2026-07".into(),
        currency: "USD".into(),
        models,
        ..PriceBook::default()
    };
    let mut message = UsageMessage {
        source_message_id: "m".into(),
        session_id: "s".into(),
        project_path: None,
        client_id: "codex".into(),
        client_version: None,
        provider_id: "openai".into(),
        model_id: "gpt-5".into(),
        observed_at: Utc::now(),
        tokens: TokenBreakdown {
            input: 1_000_000,
            output: 500_000,
            ..TokenBreakdown::default()
        },
        cost: Cost::default(),
        classification_text: None,
    };
    assert!(book.estimate(&mut message));
    assert_eq!(message.cost.amount, 6.0);
    assert_eq!(
        message.cost.pricebook_version.as_deref(),
        Some("contract-2026-07")
    );
    assert_eq!(message.cost.price_source.as_deref(), Some("manual"));
}

#[test]
fn organization_override_wins_over_openrouter_entry() {
    let mut message = UsageMessage {
        source_message_id: "m".into(),
        session_id: "s".into(),
        project_path: None,
        client_id: "opencode".into(),
        client_version: None,
        provider_id: "openrouter".into(),
        model_id: "moonshotai/kimi-k3".into(),
        observed_at: Utc::now(),
        tokens: TokenBreakdown {
            input: 1_000_000,
            ..TokenBreakdown::default()
        },
        cost: Cost::default(),
        classification_text: None,
    };
    let catalog = PriceCatalog {
        schema_version: PriceCatalog::SCHEMA_VERSION.into(),
        catalog_version: "company-2026-07-22".into(),
        generated_at: Utc::now(),
        currency: "USD".into(),
        entries: vec![
            PriceEntry {
                provider_id: Some("openrouter".into()),
                model_id: "moonshotai/kimi-k3".into(),
                price: ModelPrice {
                    input_per_million: 1.0,
                    ..ModelPrice::default()
                },
                currency: "USD".into(),
                authority: PriceAuthority::OpenRouter,
                source_url: None,
                retrieved_at: None,
                effective_from: None,
                effective_until: None,
                notes: None,
            },
            PriceEntry {
                provider_id: Some("openrouter".into()),
                model_id: "moonshotai/kimi-k3".into(),
                price: ModelPrice {
                    input_per_million: 0.25,
                    ..ModelPrice::default()
                },
                currency: "USD".into(),
                authority: PriceAuthority::OrganizationOverride,
                source_url: None,
                retrieved_at: None,
                effective_from: None,
                effective_until: None,
                notes: Some("contracted internal rate".into()),
            },
        ],
    }
    .into_pricebook();

    assert!(catalog.estimate(&mut message));
    assert_eq!(message.cost.amount, 0.25);
    assert_eq!(
        message.cost.price_source.as_deref(),
        Some("organization_override")
    );
}

#[test]
fn parses_openrouter_dollar_per_token_prices_into_per_million_rates() {
    let body = r#"{
      "data": [{
        "id": "moonshotai/kimi-k3",
        "canonical_slug": "moonshotai/kimi-k3-20260715",
        "pricing": {
          "prompt": "0.00000024",
          "completion": "0.00000200",
          "input_cache_read": "0.00000012",
          "input_cache_write": "0.00000030",
          "internal_reasoning": "0.00000050"
        }
      }]
    }"#;

    let catalog = PriceCatalog::from_openrouter_json(body, Utc::now()).unwrap();
    let price = &catalog.entries[0].price;
    assert_eq!(price.input_per_million, 0.24);
    assert_eq!(price.output_per_million, 2.0);
    assert_eq!(price.cache_read_per_million, 0.12);
    assert_eq!(price.cache_write_per_million, 0.3);
    assert_eq!(price.reasoning_per_million, 0.5);
}
