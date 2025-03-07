use sqlx::{postgres::PgPoolOptions, query_scalar, query, query_as};
use crate::models::{User, Auth};
use dotenv::dotenv;

#[allow(dead_code)]
impl Auth {

    pub async fn new(db_url: String) -> Result<Self, sqlx::Error> {
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
        query_as!(
            User, 
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

   pub async fn user_login(&self, user: User) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT * FROM users 
            WHERE (username = $1 AND password = $3) OR (email = $2 AND password = $3)
            "#,
            user.username,
            user.email,
            user.password
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(user)

    }


    
    pub async fn delete_user(&self, user: User) -> Result<(), sqlx::Error> {
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
    
    async fn user_exists(&self, user: User) -> Result<bool, sqlx::Error> {
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
        .fetch_one(&self.db)
        .await?;

        Ok(result.unwrap_or(false))

    }
}

impl User {
    pub async fn new(username: &str, email: &str, password: &str) -> User {
        User {id: None, username: username.to_string(), email: Some(email.to_string()), password: password.to_string(), created_at: None}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[cfg_attr(feature = "db-test", tokio::test)]
    #[serial]
    async fn test_table_creation() {
        dotenv().ok();
        let db_url: String = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");
        let auth = Auth::new(db_url).await.unwrap();

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

    #[cfg_attr(feature = "db-test", tokio::test)]
    #[serial]
    async fn test_user_registration() {
        dotenv().ok();
        let db_url: String = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");
        let auth = Auth::new(db_url).await.unwrap();

        let user = User {
            id: None,
            username : "test".to_string(),
            email: Some("test@test.com".to_string()),
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

    #[cfg_attr(feature = "db-test", tokio::test)]
    #[serial]
    async fn test_user_exists() {
        dotenv().ok();
        let db_url: String = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");
        let auth = Auth::new(db_url).await.unwrap();

        let user = User {
            id: None,
            username : "test".to_string(),
            email: Some("test@test.com".to_string()),
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

    #[cfg_attr(feature = "db-test", tokio::test)]
    #[serial]
    async fn test_delete_user() {
        dotenv().ok();
        let db_url: String = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");
        let auth = Auth::new(db_url).await.unwrap();

        let user = User {
            id: None,
            username : "test".to_string(),
            email: Some("test@test.com".to_string()),
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

    #[cfg_attr(feature = "db-test", tokio::test)]
    #[serial]
    async fn test_login() {

        dotenv().ok();
        let db_url: String = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");
        let auth = Auth::new(db_url).await.unwrap();

        let user = User {
            id: None,
            username : "test".to_string(),
            email: Some("test@test.com".to_string()),
            password: "test".to_string(),
            created_at: None,

        };

        auth.delete_user(user.clone()).await;
        let result = match auth.user_login(user.clone()).await {
            Ok(val) => val,
            Err(e) => panic!("DB error: {}", e),
        };
        assert!(result.is_none());
        
        auth.register_user(user.clone()).await;
        let result = match auth.user_login(user.clone()).await {
            Ok(val) => val,
            Err(e) => panic!("DB error: {}", e),
        };
        assert!(!(result.is_none()));
        
    }
}
