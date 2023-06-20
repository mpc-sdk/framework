use axum::{
    Router,
};
use std::net::SocketAddr;
use tower_http::{
    services::ServeDir,
    trace::TraceLayer,
};
use axum_server::Handle;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    let bindings = ServeDir::new("../bindings/pkg");
    let gg20 = ServeDir::new("../tests/e2e/gg20");
    Router::new()
        .nest_service("/pkg", bindings)
        .nest_service("/gg20", gg20)
}

async fn serve(handle: Handle, app: Router, port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    axum_server::bind(addr)
        .handle(handle)
        .serve(app.layer(TraceLayer::new_for_http()).into_make_service())
        .await.unwrap();
}
