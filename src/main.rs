use shadowmap::cli::ShadowMapCLI;
use shadowmap::BoxError;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    ShadowMapCLI::run().await
}
