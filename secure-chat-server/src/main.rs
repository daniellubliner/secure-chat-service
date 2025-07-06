use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    Json, Router,
    extract::{Path, State, ws::{Message, WebSocket, WebSocketUpgrade}},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};
use dotenv::dotenv;
use password_hash::SaltString;
use rand::rngs::OsRng;
use std::env;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc},
};
mod auth;
mod handlers;
use crate::handlers::{
    register_user,
    login_user,
    get_my_profile,
    list_users,
    get_user_profile,
    create_conversation,
    list_conversations,
    get_conversation,
    ws_join_conversation,
};
use crate::auth::{create_jwt, verify_jwt};
use uuid::Uuid;
use futures_util::{StreamExt, SinkExt};
use serde::{Deserialize, Serialize};

type Tx = mpsc::UnboundedSender<Message>;

#[derive(Deserialize)]
struct RegisterPayload {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

#[derive(Debug, Clone, Serialize)]
struct User {
    username: String,

    #[serde(skip_serializing)]
    password_hash: String,

    id: Uuid,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct UsersList {
    users: Vec<User>,
}

#[derive(Debug, Deserialize)]
struct CreateConvoRequest {
    participants: Vec<String>,
    topic: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct Conversation {
    id: String,
    participants: Vec<String>,
    topic: Option<String>,
}

#[derive(Clone)]
struct AppState {
    pub rooms: Arc<RwLock<HashMap<String, Vec<Tx>>>>,
    conversations: Arc<RwLock<HashMap<String, Conversation>>>,
    users: Arc<Mutex<HashMap<String, User>>>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    dotenv().ok();
    let _secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set.");

    let app_state = AppState {
        rooms: Arc::new(RwLock::new(HashMap::new())),
        conversations: Arc::new(RwLock::new(HashMap::new())),
        users: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        .route("/me", get(get_my_profile))
        .route("/users", get(list_users))
        .route("/users/{id}", get(get_user_profile))
        .route(
            "/conversations",
            post(create_conversation).get(list_conversations),
        )
        .route("/conversations/{id}", get(get_conversation))
        .route("/ws/conversations/{id}", get(ws_join_conversation))
        .with_state(app_state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
