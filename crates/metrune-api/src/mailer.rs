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
            // Running without mail is a supported deployment choice: invitations
            // return a manual link, while password reset is unavailable because
            // its token must be delivered only to the account owner.
            if environment == "production" {
                tracing::warn!(
                    "SMTP is not configured. Invitations return a manual link, and password \
                     reset is unavailable. Set METRUNE_SMTP_HOST, METRUNE_SMTP_PORT, \
                     METRUNE_SMTP_USERNAME, METRUNE_SMTP_PASSWORD, METRUNE_SMTP_FROM, and \
                     METRUNE_SMTP_SECURITY to enable delivery."
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
        let html = layout(
            &format!("Accept your invitation to {organization_name} on Metrune."),
            "You've been invited",
            &format!(
                "You were invited to join <strong>{}</strong> on Metrune as <strong>{}</strong>.",
                escape_html(organization_name),
                escape_html(role),
            ),
            "Accept invitation",
            &link,
            "This single-use link expires soon. If you did not expect this invitation, \
             you can ignore this email.",
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
        let html = layout(
            "Choose a new password for your Metrune account.",
            "Reset your password",
            "A password reset was requested for your Metrune account.",
            "Choose a new password",
            &link,
            "This single-use link expires soon. If you did not request this reset, \
             you can ignore this email.",
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

/// Wrap one call to action in the shared Metrune email shell.
///
/// Mail clients strip `<style>` blocks and most modern CSS, so this is a
/// centred table with inline attributes only. The button is a table cell with a
/// `bgcolor` rather than a styled anchor, because Outlook drops background
/// colours on links. `intro` is already-escaped HTML; every other caller-supplied
/// value is escaped here.
fn layout(
    preheader: &str,
    heading: &str,
    intro: &str,
    cta: &str,
    link: &str,
    note: &str,
) -> String {
    const FONT: &str = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
    let link = escape_html(link);
    format!(
        "<!doctype html><html><body style=\"margin:0;padding:0;background-color:#f4f7fc;\">\
         <div style=\"display:none;max-height:0;overflow:hidden;opacity:0;\">{preheader}</div>\
         <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" \
         style=\"background-color:#f4f7fc;\"><tr><td align=\"center\" style=\"padding:32px 16px;\">\
         <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" \
         style=\"max-width:520px;\">\
         <tr><td style=\"padding-bottom:20px;font-family:{FONT};font-size:18px;font-weight:700;\
         letter-spacing:0.3px;color:#001553;\">Metrune</td></tr>\
         <tr><td style=\"background-color:#ffffff;border:1px solid #dde4f0;border-radius:12px;\
         padding:32px;font-family:{FONT};\">\
         <p style=\"margin:0 0 12px;font-size:20px;line-height:28px;font-weight:600;color:#001553;\">\
         {heading}</p>\
         <p style=\"margin:0 0 24px;font-size:15px;line-height:24px;color:#5f6b8f;\">{intro}</p>\
         <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>\
         <td bgcolor=\"#0070e0\" style=\"border-radius:8px;\">\
         <a href=\"{link}\" style=\"display:inline-block;padding:12px 24px;font-family:{FONT};\
         font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;\">{cta}</a>\
         </td></tr></table>\
         <p style=\"margin:24px 0 4px;font-size:13px;line-height:20px;color:#5f6b8f;\">\
         Or paste this link into your browser:</p>\
         <p style=\"margin:0;font-size:13px;line-height:20px;word-break:break-all;\">\
         <a href=\"{link}\" style=\"color:#0059bd;\">{link}</a></p>\
         </td></tr>\
         <tr><td style=\"padding:20px 4px 0;font-family:{FONT};font-size:12px;line-height:18px;\
         color:#5f6b8f;\">{note}</td></tr>\
         </table></td></tr></table></body></html>",
        preheader = escape_html(preheader),
        heading = escape_html(heading),
        cta = escape_html(cta),
        note = escape_html(note),
    )
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
    use super::{escape_html, layout, normalize_email, SmtpEnvironment};

    #[test]
    fn email_html_escapes_operator_controlled_values() {
        assert_eq!(
            escape_html("<Team & \"friends\">"),
            "&lt;Team &amp; &quot;friends&quot;&gt;"
        );
    }

    #[test]
    fn email_layout_escapes_every_value_except_the_prepared_intro() {
        let html = layout(
            "<preheader>",
            "<heading>",
            "<strong>already escaped</strong>",
            "<cta>",
            "https://example.test/accept#a\"b",
            "<note>",
        );
        // The intro is prepared by the caller, which escapes the organization
        // name and role before marking them up, so its tags must survive.
        assert!(html.contains("<strong>already escaped</strong>"));
        for raw in ["<preheader>", "<heading>", "<cta>", "<note>"] {
            assert!(!html.contains(raw), "{raw} reached the document unescaped");
        }
        // The link lands in an href and in the visible fallback, so a quote in
        // it must not be able to close the attribute.
        assert!(html.contains("a&quot;b"));
        assert!(!html.contains("accept#a\"b"));
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
        // No configuration at all is a supported deployment choice and must
        // read as empty, which is what lets the API start without a mailer.
        assert!(SmtpEnvironment::default().is_empty());

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
