use sqlx::{postgres::PgPoolOptions, query_scalar, query, query_as};
use crate::models::{User, Auth};
use dotenv::dotenv;

#[allow(dead_code)]
impl Auth {

    pub async fn new() -> Result<Self, sqlx::Error> {
        dotenv().ok();
        let db_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set");
        println!("URL: {}", db_url);  // Debug print

        let db = PgPoolOptions::new()
            .connect(&db_url)
            .await?;

        let auth = Self {db};
        auth.setup().await?;

        Ok(auth)
    }

    async fn setup(&self) -> Result<(), sqlx::Error> {
        let table_exists = query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 
                FROM information_schema.tables 
                WHERE table_name = 'users'
            )
            "#
        )
        .fetch_one(&self.db)
        .await?
        .unwrap_or(false);

        if !table_exists {
            // Create users table
            query!(
                r#"
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                "#
            )
            .execute(&self.db)
            .await?;
        }

        Ok(())
    }

    pub async fn register_user(&self, user: User /*username: &str, password: &str, email: &str*/) -> Result<User, sqlx::Error> {
        if self.user_exists(user.clone()).await? {
            Err::<(), sqlx::Error>(sqlx::Error::RowNotFound);
        }
        // Insert user and return all fields
        query_as!(
            User,  // This will return the created user
            r#"
            INSERT INTO users (username, email, password, created_at)
            VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
            RETURNING id, username, email, password, created_at
            "#,
            user.username,
            user.email,
            user.password,
        )
        .fetch_one(&self.db)
        .await
            
    }

    async fn user_exists(&self, user: User) -> Result<bool, sqlx::Error> {
        let exists = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM users 
                WHERE username = $1 OR email = $2
            )
            "#,
            user.username,
            user.email
        )
        .fetch_one(&self.db)
        .await?;

        Ok(exists.unwrap_or(false))
    }

    async fn delete_user(&self, user: User) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            DELETE FROM users 
            WHERE username = $1 AND email = $2
            "#,
            user.username,
            user.email
        )
        .execute(&self.db)
        .await
        .map(|_| ())

    }

}

impl User {
    pub async fn new(username: &str, email: &str, password: &str) -> User {
        User {id: None, username: username.to_string(), email: email.to_string(), password: password.to_string(), created_at: None}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[cfg_attr(feature = "test-util", tokio::test)]
    #[serial]
    async fn test_table_creation() {
        dotenv().ok();
        let auth = Auth::new().await.unwrap();

        let result = sqlx::query!(
            r#"
            SELECT id, username, email, password, created_at 
            FROM users 
            LIMIT 0
            "#
        )
        .fetch_all(&auth.db)
        .await;

        assert!(result.is_ok(), "Users table doesn't exist or has wrong structure");
    }

    // Serial because it changes state of DB
    #[cfg_attr(feature = "test-util", tokio::test)]
    #[serial]
    async fn test_user_registration() {
        dotenv().ok();
        let auth = Auth::new().await.unwrap();

        let user = User {
            id: None,
            username : "test".to_string(),
            email: "test@test.com".to_string(),
            password: "test".to_string(),
            created_at: None,

        };

        sqlx::query!(
            r#"
            DELETE FROM users 
            WHERE username = $1 OR email = $2
            "#,
            user.username,
            user.email
        )
        .execute(&auth.db)
        .await;

        let exists = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM users 
                WHERE username = $1 OR email = $2
            )
            "#,
            user.username,
            user.email
        )
        .fetch_one(&auth.db)
        .await;

        assert_eq!(exists.unwrap(), Some(false));

        auth.register_user(user.clone()).await.unwrap();

        let exists = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM users 
                WHERE username = $1 OR email = $2
            )
            "#,
            user.username,
            user.email
        )
        .fetch_one(&auth.db)
        .await;

        assert_eq!(exists.unwrap(), Some(true));

    }

    #[cfg_attr(feature = "test-util", tokio::test)]
    #[serial]
    async fn test_user_exists() {
        dotenv().ok();
        let auth = Auth::new().await.unwrap();

        let user = User {
            id: None,
            username : "test".to_string(),
            email: "test@test.com".to_string(),
            password: "test".to_string(),
            created_at: None,

        };

        let result = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM users 
                WHERE username = $1 OR email = $2
            )
            "#,
            user.username,
            user.email
        )
        .fetch_one(&auth.db)
        .await;

        let exists = auth.user_exists(user.clone()).await.unwrap();
        assert_eq!(result.unwrap(), Some(exists))

    }

    #[cfg_attr(feature = "test-util", tokio::test)]
    #[serial]
    async fn test_delete_user() {
        dotenv().ok();

        let auth = Auth::new().await.unwrap();

        let user = User {
            id: None,
            username : "test".to_string(),
            email: "test@test.com".to_string(),
            password: "test".to_string(),
            created_at: None,

        };

        auth.delete_user(user.clone()).await.unwrap();
        auth.register_user(user.clone()).await.unwrap();
        let exists = auth.user_exists(user.clone()).await.unwrap();
        assert_eq!(exists, true);        

        auth.delete_user(user.clone()).await.unwrap();
        let exists = auth.user_exists(user.clone()).await.unwrap();
        assert_eq!(exists, false);        


    }
}
