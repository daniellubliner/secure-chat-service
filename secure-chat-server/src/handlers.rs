pub mod handlers {
    #[axum::debug_handler]
    pub async fn register_user(
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
    pub async fn login_user(
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

    pub async fn get_my_profile(
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

    pub async fn list_users(
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

    pub async fn get_user_profile(
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

    pub async fn create_conversation(
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

    pub async fn list_conversations(
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        let conversations = state.conversations.read().await;
        let list: Vec<_> = conversations.values().cloned().collect();
        Json(list)
    }

    pub async fn get_conversation(
        Path(id): Path<Uuid>,
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        let conversations = state.conversations.read().await;
        if let Some(convo) = conversations.get(&id.to_string()) {
            Json(convo.clone()).into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    }

    pub async fn ws_join_conversation(
        Path(convo_id): Path<String>,
        State(state): State<AppState>,
        ws: WebSocketUpgrade, 
    ) -> impl IntoResponse {
        ws.on_upgrade(move |socket| handle_websocket(socket, convo_id, state))
    }

    pub async fn handle_websocket(
        socket: WebSocket,
        convo_id: String,
        state: AppState,
    ) {

        let (mut sender, mut receiver) = socket.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        {
            let mut rooms = state.rooms.write().await;
            rooms.entry(convo_id.clone())
                .or_default()
                .push(tx.clone());
        }

        // Spawn task to send messages to this WebSocket from broadcast channel
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if sender.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Listen to messages from client and broadcast them
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg {
                let broadcast = Message::Text(text.clone());

                let rooms = state.rooms.read().await;
                if let Some(participants) = rooms.get(&convo_id) {
                    for user in participants {
                        let _ = user.send(broadcast.clone());
                    }
                }
            }
        }

        // Remove sender from room on disconnect
        {
            let mut rooms = state.rooms.write().await;
            if let Some(participants) = rooms.get_mut(&convo_id) {
                participants.retain(|s| !s.is_closed());

                // Clean up empty rooms
                if participants.is_empty() {
                    rooms.remove(&convo_id);
                }
            }
        }
    }
}