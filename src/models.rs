//use chrono::{DateTime, Utc};

#[allow(unused_must_use)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Option<i32>,
    pub username: String,
    pub email: String,
    pub password: String,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[allow(unused_must_use)]
#[derive(Debug)]
pub struct Auth {
    pub db: sqlx::PgPool
}
