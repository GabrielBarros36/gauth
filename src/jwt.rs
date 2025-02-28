use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use dotenv::dotenv;
use crate::models::{Claims, User};

// Move .env usage to main runtime later
fn issue_token(user: User) -> String {
	dotenv().ok();
	let key = std::env::var("JWT_SECRET").unwrap();

	let claim = Claims {
		sub: user.username,
		exp: 100000000,
		//iat: chrono::offset::Utc::now().into(),
	};

	let token = match encode(&Header::default(), &claim, &EncodingKey::from_secret(key.as_bytes())) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    token
}

//DELETE LATER
fn main() {
	dotenv().ok();
	let key = std::env::var("JWT_SECRET");

}