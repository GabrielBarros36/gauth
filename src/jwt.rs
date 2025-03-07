use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use dotenv::dotenv;
use crate::models::{Claims, User};

// Move .env usage to main runtime later
pub async fn issue_token(user: &User) -> String {
	dotenv().ok();
	let key = std::env::var("JWT_SECRET").unwrap();

	let claim = Claims {
		sub: user.username.clone(),
		exp: 1000000000000000, // REMINDER - without iat this counts from Unix epoch
		//iat: chrono::offset::Utc::now().into(),
	};

	let token = match encode(&Header::default(), &claim, &EncodingKey::from_secret(key.as_bytes())) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    token
}

// Should probably do away w/ this
// Returns true if token is valid
// Should probably move the algorithm object to runtime later
pub async fn validate_token(token: &String) -> bool {
	dotenv().ok();
	let key = std::env::var("JWT_SECRET").unwrap();

	let mut validation = Validation::new(Algorithm::HS256);

	match decode::<Claims>(&token, &DecodingKey::from_secret(key.as_bytes()), &validation) {
		Err(e) => {dbg!(e); false},
		Ok(_) => true,
	}
}

#[cfg(test)]
mod tests {
	use super::*;


	#[cfg(feature = "jwt-test")]
    #[tokio::test]
	async fn issue_and_validate() {

		let user = User {
            id: None,
            username : "test".to_string(),
            email: Some("test@test.com".to_string()),
            password: "test".to_string(),
            created_at: None,

        };

        let token : String = issue_token(&user).await;
        let validation: bool = validate_token(&token).await;
        dbg!(validation);
        assert_eq!(validation, true);

	}

}