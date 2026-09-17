use sqlx::mysql::MySqlPoolOptions;

pub type DbPool = sqlx::MySqlPool;

pub async fn connect(database_url: &str) -> anyhow::Result<DbPool> {
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &DbPool) -> anyhow::Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    Ok(())
}
