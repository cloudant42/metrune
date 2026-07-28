mod app;
mod distribution;
mod error;
mod identity;
mod limits;
mod mailer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::run().await
}
