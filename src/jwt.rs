use crate::models::{Claims, User};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation, errors};

// Move .env usage to main runtime later
pub async fn issue_token(user: &User, key: String) -> String {
    let claim = Claims {
        sub: user.username.clone(),
        exp: 1000000000000000, // REMINDER - without iat this counts from Unix epoch
                               //iat: chrono::offset::Utc::now().into(),
    };

    let token = match encode(
        &Header::default(),
        &claim,
        &EncodingKey::from_secret(key.as_bytes()),
    ) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    token
}

// Should probably do away w/ this
// Returns true if token is valid
// Should probably move the algorithm object to runtime later
pub async fn validate_token(token: &str, key: String) -> Result<Claims, errors::Error> {
    let data = decode::<Claims>(
        token, 
        &DecodingKey::from_secret(key.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)

}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "jwt-test")]
    #[tokio::test]
    async fn issue_and_validate() {
        let user = User {
            id: None,
            username: "test".to_string(),
            email: Some("test@test.com".to_string()),
            password: "test".to_string(),
            created_at: None,
        };
        let key = String::from("test");
        let token: String = issue_token(&user, key.clone()).await;
        let validation: bool = validate_token(&token, key).await;
        dbg!(validation);
        assert_eq!(validation, true);
    }
}
