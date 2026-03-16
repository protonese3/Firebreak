mod engine;
mod mcp;
mod report;
mod safety;
mod store;
mod tools;
pub mod types;
mod rls;
mod vcvd;

use axum::{routing::post, Router};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

pub struct AppState {
    pub store: store::Store,
    pub engine: engine::Engine,
    pub safety: safety::Safety,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("firebreak=info".parse().unwrap()),
        )
        .init();

    std::fs::create_dir_all("data").ok();

    let store = store::Store::new("data/firebreak.db")
        .expect("Failed to initialize database");
    let engine = engine::Engine::new();
    let safety = safety::Safety::new(10);

    let state = Arc::new(AppState { store, engine, safety });

    let app = Router::new()
        .route("/mcp", post(mcp::handler::handle_mcp))
        .with_state(state)
        .layer(CorsLayer::permissive());

    let host = std::env::var("FIREBREAK_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = std::env::var("FIREBREAK_PORT").unwrap_or_else(|_| "9090".into());
    let addr = format!("{host}:{port}");

    tracing::info!("Firebreak MCP server listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
