use anyhow::{bail, Context};
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use std::{env, time::Duration};

const SMTP_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) fn normalize_email(value: &str) -> anyhow::Result<String> {
    let trimmed = value.trim();
    if trimmed.len() > 320 {
        bail!("email address is too long");
    }
    let address = trimmed
        .parse::<lettre::Address>()
        .context("email address is invalid")?;
    Ok(address.to_string().to_ascii_lowercase())
}

#[derive(Clone)]
pub(crate) struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    public_url: String,
}

impl Mailer {
    pub(crate) fn from_env(environment: &str) -> anyhow::Result<Option<Self>> {
        let values = SmtpEnvironment::read();
        if values.is_empty() {
            if environment == "production" {
                bail!(
                    "SMTP is required in production; configure METRUNE_SMTP_HOST, \
                     METRUNE_SMTP_PORT, METRUNE_SMTP_USERNAME, METRUNE_SMTP_PASSWORD, \
                     METRUNE_SMTP_FROM, and METRUNE_SMTP_SECURITY"
                );
            }
            return Ok(None);
        }
        let values = values.complete()?;
        let credentials = Credentials::new(values.username, values.password);
        let builder = match values.security.as_str() {
            "starttls" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&values.host)
                .context("configure STARTTLS SMTP relay")?,
            "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&values.host)
                .context("configure TLS SMTP relay")?,
            _ => bail!("METRUNE_SMTP_SECURITY must be starttls or tls"),
        };
        let transport = builder
            .port(values.port)
            .credentials(credentials)
            .timeout(Some(SMTP_TIMEOUT))
            .build();
        let from = values
            .from
            .parse::<Mailbox>()
            .context("METRUNE_SMTP_FROM must be a valid mailbox")?;
        let public_url = env::var("METRUNE_PUBLIC_WEB_URL")
            .context("METRUNE_PUBLIC_WEB_URL is required when SMTP is configured")?
            .trim_end_matches('/')
            .to_owned();
        Ok(Some(Self {
            transport,
            from,
            public_url,
        }))
    }

    pub(crate) async fn send_invitation(
        &self,
        recipient: &str,
        organization_name: &str,
        role: &str,
        token: &str,
    ) -> anyhow::Result<()> {
        let link = format!("{}/accept-invite#{}", self.public_url, token);
        let subject = format!("Join {organization_name} on Metrune");
        let plain = format!(
            "You were invited to join {organization_name} on Metrune as {role}.\n\n\
             Open this single-use link to accept the invitation:\n{link}\n\n\
             The link expires soon. If you did not expect this invitation, \
             you can ignore this email."
        );
        let html = format!(
            "<p>You were invited to join <strong>{}</strong> on Metrune as <strong>{}</strong>.</p>\
             <p><a href=\"{}\">Accept invitation</a></p>\
             <p>This single-use link expires soon. If you did not expect this \
             invitation, you can ignore this email.</p>",
            escape_html(organization_name),
            escape_html(role),
            escape_html(&link),
        );
        self.send(recipient, &subject, plain, html).await
    }

    pub(crate) async fn send_password_reset(
        &self,
        recipient: &str,
        token: &str,
    ) -> anyhow::Result<()> {
        let link = format!("{}/reset-password#{}", self.public_url, token);
        let plain = format!(
            "A password reset was requested for your Metrune account.\n\n\
             Open this single-use link to choose a new password:\n{link}\n\n\
             The link expires soon. If you did not request this reset, \
             you can ignore this email."
        );
        let html = format!(
            "<p>A password reset was requested for your Metrune account.</p>\
             <p><a href=\"{}\">Choose a new password</a></p>\
             <p>This single-use link expires soon. If you did not request \
             this reset, you can ignore this email.</p>",
            escape_html(&link),
        );
        self.send(recipient, "Reset your Metrune password", plain, html)
            .await
    }

    async fn send(
        &self,
        recipient: &str,
        subject: &str,
        plain: String,
        html: String,
    ) -> anyhow::Result<()> {
        let recipient = recipient
            .parse::<Mailbox>()
            .context("recipient email is invalid")?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(recipient)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(plain),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )
            .context("build email message")?;
        self.transport
            .send(message)
            .await
            .context("SMTP delivery failed")?;
        Ok(())
    }
}

#[derive(Default)]
struct SmtpEnvironment {
    host: Option<String>,
    port: Option<String>,
    username: Option<String>,
    password: Option<String>,
    from: Option<String>,
    security: Option<String>,
}

impl SmtpEnvironment {
    fn read() -> Self {
        Self {
            host: nonempty_env("METRUNE_SMTP_HOST"),
            port: nonempty_env("METRUNE_SMTP_PORT"),
            username: nonempty_env("METRUNE_SMTP_USERNAME"),
            password: nonempty_env("METRUNE_SMTP_PASSWORD"),
            from: nonempty_env("METRUNE_SMTP_FROM"),
            security: nonempty_env("METRUNE_SMTP_SECURITY").map(|value| value.to_ascii_lowercase()),
        }
    }

    fn is_empty(&self) -> bool {
        self.host.is_none()
            && self.port.is_none()
            && self.username.is_none()
            && self.password.is_none()
            && self.from.is_none()
            && self.security.is_none()
    }

    fn complete(self) -> anyhow::Result<CompleteSmtpEnvironment> {
        Ok(CompleteSmtpEnvironment {
            host: required(self.host, "METRUNE_SMTP_HOST")?,
            port: required(self.port, "METRUNE_SMTP_PORT")?
                .parse()
                .context("METRUNE_SMTP_PORT must be a valid port")?,
            username: required(self.username, "METRUNE_SMTP_USERNAME")?,
            password: required(self.password, "METRUNE_SMTP_PASSWORD")?,
            from: required(self.from, "METRUNE_SMTP_FROM")?,
            security: required(self.security, "METRUNE_SMTP_SECURITY")?,
        })
    }
}

#[derive(Debug)]
struct CompleteSmtpEnvironment {
    host: String,
    port: u16,
    username: String,
    password: String,
    from: String,
    security: String,
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn required(value: Option<String>, name: &str) -> anyhow::Result<String> {
    value.with_context(|| format!("{name} is required when SMTP is configured"))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::{escape_html, normalize_email, SmtpEnvironment};

    #[test]
    fn email_html_escapes_operator_controlled_values() {
        assert_eq!(
            escape_html("<Team & \"friends\">"),
            "&lt;Team &amp; &quot;friends&quot;&gt;"
        );
    }

    #[test]
    fn email_normalization_trims_and_canonicalizes_case() {
        assert_eq!(
            normalize_email("  Teammate@Example.TEST  ").expect("valid email"),
            "teammate@example.test"
        );
        assert!(normalize_email("not an address").is_err());
        assert!(normalize_email(&format!("{}@example.test", "a".repeat(321))).is_err());
    }

    #[test]
    fn partial_or_invalid_smtp_configuration_fails_closed() {
        let missing = SmtpEnvironment {
            host: Some("smtp.example.test".into()),
            ..SmtpEnvironment::default()
        }
        .complete()
        .expect_err("partial SMTP configuration must not be silently disabled");
        assert!(missing.to_string().contains("METRUNE_SMTP_PORT"));

        let invalid_port = SmtpEnvironment {
            host: Some("smtp.example.test".into()),
            port: Some("not-a-port".into()),
            username: Some("user".into()),
            password: Some("secret".into()),
            from: Some("Metrune <metrune@example.test>".into()),
            security: Some("tls".into()),
        }
        .complete()
        .expect_err("an invalid SMTP port must fail startup validation");
        assert!(invalid_port
            .to_string()
            .contains("METRUNE_SMTP_PORT must be a valid port"));
    }
}
