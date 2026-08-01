//! Metrune control-plane API.
//!
//! The crate is a library so that integration tests can build the HTTP router
//! against a state they construct, rather than only being able to launch the
//! whole server. [`app::run`] is what the binary calls.

pub mod app;
mod device_auth;
mod distribution;
mod error;
mod identity;
mod limits;
mod mailer;
mod oidc;

#[cfg(test)]
mod testing;
