use sqlx::{postgres::PgPoolOptions, query_scalar, query};
mod models;
use models::{User, Auth};
use dotenv::dotenv;

impl Auth {

    pub async fn new_connection() -> Result<Self, sqlx::Error> {
        dotenv().ok();
        let db_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set");
        println!("URL: {}", db_url);  // Debug print

        let db = PgPoolOptions::new()
            .connect(&db_url)
            .await?;
        Ok(Self { db })
    }

    async fn setup(&self) -> Result<(), sqlx::Error> {
        let table_exists = sqlx::query_scalar!(
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
            sqlx::query!(
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

}
