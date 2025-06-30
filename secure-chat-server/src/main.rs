use axum::{
    routing::{get, post},
    http::StatusCode,
    Json, Router,
    extract::State,
    response::IntoResponse,
};
use axum_extra::TypedHeader;
use axum_extra::headers::{authorization::Bearer, Authorization};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use std::{collections::HashMap, sync::{Arc, Mutex}};
use argon2::{PasswordVerifier, PasswordHash, PasswordHasher, Argon2};
use rand::rngs::OsRng;
use password_hash::SaltString;
mod auth;
use crate::auth::{verify_jwt, create_jwt};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let users: Users = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        // Authentication
        .route("/register", post(register_user))
        .route("/login", post(login_user))

        // User management
        .route("/me", get(get_my_profile))
        .route("/users", get(list_users))
        .route("/users/{id}", get(get_user_profile))

        // Conversations
        .route("/conversations", post(create_conversation).get(list_conversations))
        .route("/conversations/{id}", get(get_conversation))
        .route("/conversations/{id}/join", post(join_conversation))

        // Messages
        .route("/messages", post(send_message))
        .route("/messages/{conversation_id}", get(get_messages))

        // WebSocket for real-time chat
        .route("/ws", get(handle_websocket))
        .with_state(users);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

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

#[derive(Deserialize)]
struct MyProfile {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

type Users = Arc<Mutex<HashMap<String, String>>>;

#[axum::debug_handler]
async fn register_user(
    State(users): State<Users>,
    Json(payload): Json<RegisterPayload>,
) -> StatusCode {
    let mut users = users.lock().unwrap();

    if users.contains_key(&payload.username) {
        return StatusCode::CONFLICT;
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(payload.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    users.insert(payload.username.clone(), hash);
    println!("Registered user: {}", payload.username);
    StatusCode::CREATED
}

#[axum::debug_handler]
async fn login_user(
    State(users): State<Users>,
    Json(payload): Json<LoginPayload>
) -> Result<Json<LoginResponse>, StatusCode> {

    let users = users.lock().unwrap();

    let hashed_pw = users.get(&payload.username)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(hashed_pw).unwrap();
    if argon2.verify_password(payload.password.as_bytes(), &parsed_hash).is_ok() {
        let token = create_jwt(&payload.username);
        Ok(Json(LoginResponse { token }))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn get_my_profile(
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    State(users): State<Users>,
) -> impl IntoResponse {
    // TODO: Return authenticated user profile
    let token = bearer.token();
    let claims = match verify_jwt(token) {
        Ok(claims) => claims,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let users = users.lock().unwrap();
    if let Some(profile) = users.get(&claims.subject) {
        return Json(profile.clone()).into_response();
    };

    StatusCode::NOT_FOUND.into_response()
}

async fn list_users() -> StatusCode {
    // TODO: List users
    StatusCode::NOT_IMPLEMENTED
}

async fn get_user_profile() -> StatusCode {
    // TODO: Get a user's public profile
    StatusCode::NOT_IMPLEMENTED
}

async fn create_conversation() -> StatusCode {
    // TODO: Create new conversation
    StatusCode::NOT_IMPLEMENTED
}

async fn list_conversations() -> StatusCode {
    // TODO: List user's conversations
    StatusCode::NOT_IMPLEMENTED
}

async fn get_conversation() -> StatusCode {
    // TODO: Get conversation details
    StatusCode::NOT_IMPLEMENTED
}

async fn join_conversation() -> StatusCode {
    // TODO: Join conversation
    StatusCode::NOT_IMPLEMENTED
}

async fn send_message() -> StatusCode {
    // TODO: Send a chat message
    StatusCode::NOT_IMPLEMENTED
}

async fn get_messages() -> StatusCode {
    // TODO: Get messages in conversation
    StatusCode::NOT_IMPLEMENTED
}

async fn handle_websocket() -> StatusCode {
    // TODO: Handle websocket connection
    StatusCode::NOT_IMPLEMENTED
}