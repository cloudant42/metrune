mod app;
mod credentials;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::run().await
}
