use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};
use dotenv::dotenv;
use password_hash::SaltString;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::env;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    net::TcpListener,
    sync::RwLock,
};
mod auth;
use crate::auth::{create_jwt, verify_jwt};
use uuid::Uuid;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    dotenv().ok();
    let _secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set.");

    //let users: Users = Arc::new(Mutex::new(HashMap::new()));
    let app_state = AppState {
        conversations: Arc::new(RwLock::new(HashMap::new())),
        users: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        // Authentication
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        // User management
        .route("/me", get(get_my_profile))
        .route("/users", get(list_users))
        .route("/users/{id}", get(get_user_profile))
        // Conversations
        .route(
            "/conversations",
            post(create_conversation).get(list_conversations),
        )
        .route("/conversations/{id}", get(get_conversation))
        .route("/conversations/{id}/join", post(join_conversation))
        // Messages
        .route("/messages", post(send_message))
        .route("/messages/{conversation_id}", get(get_messages))
        // WebSocket for real-time chat
        .route("/ws", get(handle_websocket))
        .with_state(app_state);

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
    conversations: Arc<RwLock<HashMap<String, Conversation>>>,
    users: Arc<Mutex<HashMap<String, User>>>,
}

#[axum::debug_handler]
async fn register_user(
    State(state): State<AppState>,
    Json(payload): Json<RegisterPayload>,
) -> StatusCode {
    let mut users = state.users.lock().unwrap();

    if users.contains_key(&payload.username) {
        return StatusCode::CONFLICT;
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let user_id: Uuid = Uuid::new_v4();

    users.insert(
        payload.username.clone(),
        User {
            username: payload.username.clone(),
            id: user_id,
            password_hash: hash,
        },
    );

    StatusCode::CREATED
}

#[axum::debug_handler]
async fn login_user(
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let users = state.users.lock().unwrap();
    let user = users
        .get(&payload.username)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&user.password_hash).unwrap();
    if argon2
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        let token = create_jwt(&payload.username);
        Ok(Json(LoginResponse { token }))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn get_my_profile(
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let token = bearer.token();
    let claims = match verify_jwt(token) {
        Ok(claims) => claims,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let users = state.users.lock().unwrap();
    if let Some(user) = users.get(&claims.sub) {
        return Json(user.clone()).into_response();
    };

    StatusCode::NOT_FOUND.into_response()
}

async fn list_users(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<UsersList>, StatusCode> {
    let token = bearer.token();
    let _claims = match verify_jwt(token) {
        Ok(claims) => claims,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    let users = state.users.lock().unwrap();
    let user_list = UsersList {
        users: users.values().cloned().collect(),
    };

    Ok(Json(user_list))
}

async fn get_user_profile(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<User>, StatusCode> {
    let token = bearer.token();
    let _claims = match verify_jwt(token) {
        Ok(claims) => claims,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    let users = state.users.lock().unwrap();
    if let Some(user) = users.values().find(|user| user.id == id) {
        Ok(Json(user.clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn create_conversation(
    State(state): State<AppState>,
    Json(payload): Json<CreateConvoRequest>,
) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    let convo = Conversation {
        id: id.clone(),
        participants: payload.participants,
        topic: payload.topic,
    };

    state.conversations.write().await.insert(id.clone(), convo);
    (StatusCode::CREATED, Json(id))
}

async fn list_conversations(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let conversations = state.conversations.read().await;
    let list: Vec<_> = conversations.values().cloned().collect();
    Json(list)
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
