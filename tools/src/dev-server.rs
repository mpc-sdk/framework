use axum::Router;
use axum_server::Handle;
use std::net::SocketAddr;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{
    layer::SubscriberExt, util::SubscriberInitExt,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let handle = Handle::new();
    let router = router();
    serve(handle, router, 9009).await;
}

fn router() -> Router {
    let bindings = ServeDir::new("../bindings/webassembly/pkg");
    let cggmp = ServeDir::new("../integration_tests/tests/e2e/cggmp");
    Router::new()
        .nest_service("/pkg", bindings)
        .nest_service("/cggmp", cggmp)
}

async fn serve(handle: Handle, app: Router, port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    axum_server::bind(addr)
        .handle(handle)
        .serve(
            app.layer(TraceLayer::new_for_http()).into_make_service(),
        )
        .await
        .unwrap();
}
