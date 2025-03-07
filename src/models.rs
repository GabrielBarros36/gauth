use serde::{Serialize, Deserialize};

#[allow(unused_must_use)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Option<i32>,
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[allow(unused_must_use)]
#[derive(Debug)]
pub struct Auth {
    pub db: sqlx::PgPool
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,         // Username
    pub exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    //iat: usize,          // Optional. Issued at (as UTC timestamp)
}