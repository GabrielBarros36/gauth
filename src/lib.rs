use sqlx::{postgres::PgPoolOptions, query_scalar, query, query_as};
mod models;
use models::{User, Auth};
use dotenv::dotenv;

impl Auth {

    pub async fn new_connection(&self) -> Result<Self, sqlx::Error> {
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

    pub async fn register_user(&self, username: &str, password: &str, email: &str) -> Result<User, sqlx::Error> {
        if self.user_exists(username, email).await? {
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
            username,
            email,
            password,
        )
        .fetch_one(&self.db)
        .await
            
    }

    async fn user_exists(&self, username: &str, email: &str) -> Result<bool, sqlx::Error> {
        let exists = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM users 
                WHERE username = $1 OR email = $2
            )
            "#,
            username,
            email
        )
        .fetch_one(&self.db)
        .await?;

        Ok(exists.unwrap_or(false))
    }

}
