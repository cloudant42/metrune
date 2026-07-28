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
        attempts.retain(|_, window| now.duration_since(window.started_at) < LOGIN_WINDOW);
        attempts
            .get(key)
            .is_some_and(|window| window.failures >= MAX_LOGIN_FAILURES_PER_WINDOW)
    }

    pub(crate) fn record_failure(&self, key: &str) {
        let mut attempts = self.attempts.lock().expect("login limiter mutex poisoned");
        let now = Instant::now();
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
    pub(crate) invitation: RateLimit,
    pub(crate) password_reset: RateLimit,
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
            invitation: RateLimit::new(3600, 30).with_env_override("INVITATIONS_PER_HOUR"),
            password_reset: RateLimit::new(3600, 10).with_env_override("PASSWORD_RESETS_PER_HOUR"),
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
