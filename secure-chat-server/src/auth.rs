use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    exp: usize,
}

pub fn get_secret_key() -> Vec<u8> {
    std::env::var("SECRET_KEY")
        .expect("SECRET_KEY must be set")
        .into_bytes()
}

pub fn create_jwt(username: &str) -> String {
    let expiration = SystemTime::now()
        .checked_add(Duration::from_secs(60 * 60))
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: username.to_string(),
        exp: expiration,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(&get_secret_key())).unwrap()
}

pub fn verify_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&get_secret_key()),
        &Validation::new(Algorithm::HS256),
    )?;
    Ok(token_data.claims)
}