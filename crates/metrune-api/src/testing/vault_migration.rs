//! Credentials written before per-organization key derivation must survive the
//! upgrade: readable on the way in, re-sealed under the organization's key, and
//! never silently dropped.

use super::harness::harness;
use crate::app::{rewrap_legacy_credentials, AppState};
use uuid::Uuid;

/// Mirrors the constants in `app`: 0 = sealed under the master key.
const MASTER: i16 = 0;
const PER_ORGANIZATION: i16 = 1;

async fn plant_legacy_credential(
    harness: &super::harness::Harness,
    organization_id: Uuid,
    credential_id: &str,
    secret: &str,
) {
    let aad = AppState::credential_aad(organization_id, credential_id, 1);
    let (ciphertext, nonce) = harness
        .state
        .seal_under_master_key(secret, aad.as_bytes())
        .expect("seal under the master key");
    sqlx::query(
        "INSERT INTO provider_credentials(
             id, organization_id, credential_id, provider_id, version,
             ciphertext, nonce, created_at, key_derivation
         ) VALUES ($1,$2,$3,'openrouter',1,$4,$5,NOW(),$6)",
    )
    .bind(Uuid::new_v4())
    .bind(organization_id)
    .bind(credential_id)
    .bind(ciphertext)
    .bind(nonce)
    .bind(MASTER)
    .execute(&harness.postgres)
    .await
    .expect("insert the legacy credential");
}

async fn derivation_of(harness: &super::harness::Harness, organization_id: Uuid) -> i16 {
    sqlx::query_scalar::<_, i16>(
        "SELECT key_derivation FROM provider_credentials WHERE organization_id = $1",
    )
    .bind(organization_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("read the credential")
}

#[tokio::test]
async fn a_legacy_credential_is_resealed_under_its_organizations_key() {
    let harness = harness!();
    let organization_id = harness.create_organization("rewrap").await;
    plant_legacy_credential(&harness, organization_id, "openrouter", "the-secret").await;
    assert_eq!(derivation_of(&harness, organization_id).await, MASTER);

    rewrap_legacy_credentials(&harness.state)
        .await
        .expect("re-wrap the legacy credentials");

    assert_eq!(
        derivation_of(&harness, organization_id).await,
        PER_ORGANIZATION,
        "the credential was not migrated off the master key"
    );

    // The whole point of the migration is that the secret is still usable.
    let aad = AppState::credential_aad(organization_id, "openrouter", 1);
    let (ciphertext, nonce, derivation) = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, i16)>(
        "SELECT ciphertext, nonce, key_derivation FROM provider_credentials
             WHERE organization_id = $1",
    )
    .bind(organization_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("read the credential");
    let recovered = harness
        .state
        .decrypt_for_tests(
            organization_id,
            derivation,
            &ciphertext,
            &nonce,
            aad.as_bytes(),
        )
        .expect("the migrated credential must still decrypt");
    assert_eq!(recovered, "the-secret");
}

#[tokio::test]
async fn re_running_the_migration_is_a_no_op() {
    let harness = harness!();
    let organization_id = harness.create_organization("rewrap-twice").await;
    plant_legacy_credential(&harness, organization_id, "openrouter", "the-secret").await;

    rewrap_legacy_credentials(&harness.state)
        .await
        .expect("first pass");
    let after_first = sqlx::query_as::<_, (Vec<u8>, i16)>(
        "SELECT ciphertext, key_derivation FROM provider_credentials WHERE organization_id = $1",
    )
    .bind(organization_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("read the credential");

    rewrap_legacy_credentials(&harness.state)
        .await
        .expect("second pass");
    let after_second = sqlx::query_as::<_, (Vec<u8>, i16)>(
        "SELECT ciphertext, key_derivation FROM provider_credentials WHERE organization_id = $1",
    )
    .bind(organization_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("read the credential");

    assert_eq!(
        after_first, after_second,
        "a second start re-encrypted an already-migrated credential"
    );
}

#[tokio::test]
async fn an_undecryptable_credential_is_left_intact_rather_than_dropped() {
    let harness = harness!();
    let organization_id = harness.create_organization("rewrap-damaged").await;
    // Ciphertext that no key opens — e.g. the master key file was replaced.
    sqlx::query(
        "INSERT INTO provider_credentials(
             id, organization_id, credential_id, provider_id, version,
             ciphertext, nonce, created_at, key_derivation
         ) VALUES ($1,$2,'broken','openrouter',1,$3,$4,NOW(),$5)",
    )
    .bind(Uuid::new_v4())
    .bind(organization_id)
    .bind(vec![9_u8; 48])
    .bind(vec![1_u8; 12])
    .bind(MASTER)
    .execute(&harness.postgres)
    .await
    .expect("insert the damaged credential");

    // Startup must not abort because one row is unreadable.
    rewrap_legacy_credentials(&harness.state)
        .await
        .expect("a damaged credential must not fail the migration");

    let (rows, derivation) = sqlx::query_as::<_, (i64, i16)>(
        "SELECT COUNT(*), MIN(key_derivation) FROM provider_credentials
         WHERE organization_id = $1",
    )
    .bind(organization_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("read the credential");
    assert_eq!(rows, 1, "the damaged credential was deleted");
    assert_eq!(
        derivation, MASTER,
        "the damaged credential was marked migrated without being re-sealed"
    );
}
