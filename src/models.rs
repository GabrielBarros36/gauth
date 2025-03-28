use serde::{Deserialize, Serialize};

#[allow(unused_must_use)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Option<i32>,
    pub username: String,
    pub email: Option<String>,
    pub profile_picture: Option<String>,
    pub password: String,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[allow(unused_must_use)]
#[derive(Debug)]
pub struct Auth {
    pub db: sqlx::PgPool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // Username
    pub exp: u64, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
                  //iat: usize,          // Optional. Issued at (as UTC timestamp)
}
