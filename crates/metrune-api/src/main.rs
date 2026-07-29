#[tokio::main]
async fn main() -> anyhow::Result<()> {
    metrune_api::app::run().await
}
