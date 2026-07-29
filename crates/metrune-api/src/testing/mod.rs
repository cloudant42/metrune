//! HTTP-level tests for routing, authentication and authorization.
//!
//! These exercise the real router against a real Postgres, because the
//! guarantees under test — tenant isolation, role gates, credential lifetime —
//! live in SQL predicates rather than in Rust control flow.

mod harness;

mod analytics;
mod authorization;
mod identity_flows;
mod tenancy;
mod vault_migration;
