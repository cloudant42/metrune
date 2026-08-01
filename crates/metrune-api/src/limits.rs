use crate::error::ApiError;
use axum::http::HeaderMap;
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const LOGIN_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const MAX_LOGIN_FAILURES_PER_WINDOW: u32 = 5;
const MAX_RATE_LIMIT_KEYS: usize = 100_000;
// Login keys are attacker-controlled (normalized email addresses). Keep the
// account-specific limiter bounded just like the generic request limiter so a
// stream of unique addresses cannot grow the process indefinitely.
const MAX_LOGIN_KEYS: usize = 100_000;

#[derive(Clone, Default)]
pub(crate) struct LoginAttemptLimiter {
    attempts: Arc<Mutex<HashMap<String, LoginAttemptWindow>>>,
}

struct LoginAttemptWindow {
    started_at: Instant,
    failures: u32,
}

impl LoginAttemptLimiter {
    pub(crate) fn is_limited(&self, key: &str) -> bool {
        let mut attempts = self.attempts.lock().expect("login limiter mutex poisoned");
        let now = Instant::now();
        if attempts.len() >= MAX_LOGIN_KEYS {
            attempts.retain(|_, window| now.duration_since(window.started_at) < LOGIN_WINDOW);
        }
        attempts
            .get(key)
            .is_some_and(|window| window.failures >= MAX_LOGIN_FAILURES_PER_WINDOW)
    }

    pub(crate) fn record_failure(&self, key: &str) {
        let mut attempts = self.attempts.lock().expect("login limiter mutex poisoned");
        let now = Instant::now();
        if attempts.len() >= MAX_LOGIN_KEYS {
            attempts.retain(|_, window| now.duration_since(window.started_at) < LOGIN_WINDOW);
            if attempts.len() >= MAX_LOGIN_KEYS && !attempts.contains_key(key) {
                tracing::warn!(
                    "login limiter key table is full; shedding account lockout tracking"
                );
                return;
            }
        }
        let window = attempts
            .entry(key.to_owned())
            .or_insert(LoginAttemptWindow {
                started_at: now,
                failures: 0,
            });
        if now.duration_since(window.started_at) >= LOGIN_WINDOW {
            window.started_at = now;
            window.failures = 0;
        }
        window.failures = window.failures.saturating_add(1);
    }

    pub(crate) fn reset(&self, key: &str) {
        self.attempts
            .lock()
            .expect("login limiter mutex poisoned")
            .remove(key);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RateLimit {
    window: Duration,
    max_requests: u32,
}

impl RateLimit {
    pub(crate) const fn new(window_secs: u64, max_requests: u32) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            max_requests,
        }
    }

    fn with_env_override(self, name: &str) -> Self {
        match env::var(format!("METRUNE_RATE_LIMIT_{name}"))
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
        {
            Some(max_requests) => Self {
                max_requests,
                ..self
            },
            None => self,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RateLimits {
    pub(crate) enroll: RateLimit,
    pub(crate) login: RateLimit,
    pub(crate) provision: RateLimit,
    pub(crate) classify: RateLimit,
    pub(crate) ingest: RateLimit,
    pub(crate) analytics: RateLimit,
    pub(crate) enrollment_code: RateLimit,
    pub(crate) device_authorization: RateLimit,
    pub(crate) device_verification: RateLimit,
    pub(crate) device_token: RateLimit,
    pub(crate) invitation: RateLimit,
    pub(crate) password_reset: RateLimit,
    pub(crate) vault_recovery: RateLimit,
    pub(crate) organization_create: RateLimit,
}

impl RateLimits {
    pub(crate) fn from_env() -> Self {
        Self {
            enroll: RateLimit::new(60, 10).with_env_override("ENROLL_PER_MINUTE"),
            login: RateLimit::new(60, 30).with_env_override("LOGIN_PER_MINUTE"),
            provision: RateLimit::new(60, 20).with_env_override("PROVISION_PER_MINUTE"),
            classify: RateLimit::new(60, 60).with_env_override("CLASSIFY_PER_MINUTE"),
            ingest: RateLimit::new(60, 60).with_env_override("INGEST_PER_MINUTE"),
            analytics: RateLimit::new(60, 120).with_env_override("ANALYTICS_PER_MINUTE"),
            enrollment_code: RateLimit::new(3600, 20)
                .with_env_override("ENROLLMENT_CODES_PER_HOUR"),
            device_authorization: RateLimit::new(60, 10)
                .with_env_override("DEVICE_AUTHORIZATIONS_PER_MINUTE"),
            device_verification: RateLimit::new(3600, 60)
                .with_env_override("DEVICE_VERIFICATIONS_PER_HOUR"),
            device_token: RateLimit::new(60, 300)
                .with_env_override("DEVICE_TOKEN_POLLS_PER_MINUTE"),
            invitation: RateLimit::new(3600, 30).with_env_override("INVITATIONS_PER_HOUR"),
            password_reset: RateLimit::new(3600, 10).with_env_override("PASSWORD_RESETS_PER_HOUR"),
            vault_recovery: RateLimit::new(3600, 5).with_env_override("VAULT_RECOVERIES_PER_HOUR"),
            organization_create: RateLimit::new(3600, 5)
                .with_env_override("ORGANIZATIONS_PER_HOUR"),
        }
    }
}

struct RateWindow {
    expires_at: Instant,
    hits: u32,
}

#[derive(Clone, Default)]
pub(crate) struct RateLimiter {
    windows: Arc<Mutex<HashMap<String, RateWindow>>>,
}

impl RateLimiter {
    pub(crate) fn check(&self, scope: &str, key: &str, limit: RateLimit) -> Result<(), ApiError> {
        if limit.max_requests == 0 {
            return Ok(());
        }
        let mut windows = self.windows.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        windows.retain(|_, window| window.expires_at > now);
        let entry = format!("{scope}:{key}");
        if windows.len() >= MAX_RATE_LIMIT_KEYS && !windows.contains_key(&entry) {
            tracing::warn!(scope, "rate limiter key table is full; shedding request");
            return Err(ApiError::too_many_requests("the server is shedding load"));
        }
        let window = windows.entry(entry).or_insert(RateWindow {
            expires_at: now + limit.window,
            hits: 0,
        });
        if window.hits >= limit.max_requests {
            return Err(ApiError::too_many_requests(format!(
                "rate limit exceeded for {scope}; retry later"
            )));
        }
        window.hits = window.hits.saturating_add(1);
        Ok(())
    }
}

pub(crate) fn client_address(
    headers: &HeaderMap,
    peer: SocketAddr,
    trust_proxy_headers: bool,
) -> String {
    if trust_proxy_headers {
        if let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return forwarded.to_owned();
        }
    }
    peer.ip().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn rate_limit_enforces_the_exact_budget_and_isolates_keys_and_scopes() {
        let limiter = RateLimiter::default();
        let limit = RateLimit::new(60, 2);

        assert!(limiter.check("ingest", "installation-a", limit).is_ok());
        assert!(limiter.check("ingest", "installation-a", limit).is_ok());
        let error = limiter
            .check("ingest", "installation-a", limit)
            .expect_err("the third request must exceed a budget of two");
        assert_eq!(error.status, axum::http::StatusCode::TOO_MANY_REQUESTS);

        assert!(limiter.check("ingest", "installation-b", limit).is_ok());
        assert!(limiter.check("analytics", "installation-a", limit).is_ok());
    }

    #[test]
    fn a_zero_budget_disables_rate_limiting_and_expired_windows_reopen() {
        let limiter = RateLimiter::default();
        let disabled = RateLimit::new(60, 0);
        for _ in 0..100 {
            assert!(limiter.check("disabled", "subject", disabled).is_ok());
        }

        let immediate = RateLimit::new(0, 1);
        assert!(limiter.check("short", "subject", immediate).is_ok());
        assert!(
            limiter.check("short", "subject", immediate).is_ok(),
            "a window whose deadline has passed was retained"
        );
    }

    #[test]
    fn login_attempts_lock_at_the_boundary_and_reset_after_success() {
        let limiter = LoginAttemptLimiter::default();
        for _ in 0..MAX_LOGIN_FAILURES_PER_WINDOW {
            assert!(!limiter.is_limited("account"));
            limiter.record_failure("account");
        }
        assert!(limiter.is_limited("account"));
        assert!(!limiter.is_limited("another-account"));

        limiter.reset("account");
        assert!(!limiter.is_limited("account"));
    }

    #[test]
    fn login_attempt_tracking_is_bounded_for_unique_addresses() {
        let limiter = LoginAttemptLimiter::default();
        for index in 0..MAX_LOGIN_KEYS {
            limiter.record_failure(&format!("account-{index}@example.test"));
        }
        limiter.record_failure("overflow@example.test");
        let attempts = limiter
            .attempts
            .lock()
            .expect("login limiter mutex poisoned");
        assert_eq!(attempts.len(), MAX_LOGIN_KEYS);
        assert!(!attempts.contains_key("overflow@example.test"));
    }

    #[test]
    fn forwarded_addresses_are_ignored_unless_proxy_trust_is_explicit() {
        let peer = SocketAddr::from(([10, 0, 0, 7], 43100));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.9, 198.51.100.2"),
        );

        assert_eq!(client_address(&headers, peer, false), "10.0.0.7");
        assert_eq!(client_address(&headers, peer, true), "203.0.113.9");
    }
}
