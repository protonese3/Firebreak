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

fn data_dir() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let base = exe.parent().unwrap_or(std::path::Path::new("."));
    let dir = base.join("data");
    std::fs::create_dir_all(&dir).ok();
    dir
}

fn init_state() -> Arc<AppState> {
    let db_path = data_dir().join("firebreak.db");

    let store = store::Store::new(db_path.to_str().unwrap_or("data/firebreak.db"))
        .expect("Failed to initialize database");
    let engine = engine::Engine::new();
    let safety = safety::Safety::new(10);

    Arc::new(AppState { store, engine, safety })
}

#[tokio::main]
async fn main() {
    let stdio_mode = std::env::args().any(|a| a == "--stdio");

    if !stdio_mode {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::from_default_env()
                    .add_directive("firebreak=info".parse().unwrap()),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::from_default_env()
                    .add_directive("firebreak=error".parse().unwrap()),
            )
            .with_writer(std::io::stderr)
            .init();
    }

    let state = init_state();

    if stdio_mode {
        mcp::stdio::run(state).await;
    } else {
        let host = std::env::var("FIREBREAK_HOST").unwrap_or_else(|_| "0.0.0.0".into());
        let port = std::env::var("FIREBREAK_PORT").unwrap_or_else(|_| "9090".into());
        let addr = format!("{host}:{port}");

        tracing::info!("Firebreak MCP server listening on {addr}");

        let app = Router::new()
            .route("/mcp", post(mcp::handler::handle_mcp))
            .with_state(state)
            .layer(CorsLayer::permissive());

        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}
