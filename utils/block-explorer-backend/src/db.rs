use indoc::indoc;
use serde_json::Value;
use sqlx::{PgPool, Postgres, QueryBuilder};
use tracing::info;

use crate::models::{self as m};

#[derive(Clone)]
pub struct Db {
    // `PgPool` is an `Arc` internally, so it's cheaply clonable.
    pool: PgPool,
}

impl Db {
    pub async fn new(db_connection_url: &str) -> anyhow::Result<Self> {
        // TODO: obscure the connection URL in the log, as it may contain
        // sensitive information.
        info!(url = db_connection_url, "Connecting to database...");

        let db = Self {
            pool: PgPool::connect(&db_connection_url).await?,
        };

        info!("Running migrations...");
        db.run_migrations().await?;

        info!("Database initialization successful.");

        Ok(db)
    }

    async fn run_migrations(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }
}

/// Read operations.
impl Db {
    pub async fn get_tx_by_hash(&self, tx_hash: &m::HexString) -> anyhow::Result<Option<Value>> {
        let row_opt: Option<(Value,)> = sqlx::query_as(indoc!(
            r#"
            SELECT blob FROM transactions
            WHERE blob->>'tx_hash' = $1
            LIMIT 1
            "#
        ))
        .bind(tx_hash.to_string())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row_opt.map(|r| r.0))
    }

    pub async fn get_block_by_hash(&self, hash: &m::HexString) -> anyhow::Result<Vec<Value>> {
        let rows: Vec<(Value,)> = sqlx::query_as(indoc!(
            r#"
            SELECT blob FROM blocks
            WHERE blob->>'hash' = $1
            "#
        ))
        .bind(hash.to_string())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|v| v.0).collect())
    }

    pub async fn get_events(&self, query: &m::EventsQuery) -> anyhow::Result<Vec<m::Event>> {
        let mut query_builder =
            WhereClausesBuilder::new(QueryBuilder::new("SELECT (id, key, value) FROM events"));

        if let Some(event_id) = query.id {
            query_builder.push_condition("id = ");
            query_builder.query.push_bind(event_id);
        }
        if let Some(tx_hash) = &query.tx_hash {
            query_builder.push_condition("tx_hash = ");
            query_builder.query.push_bind(&tx_hash.0);
        }
        if let Some(tx_height) = query.tx_height {
            query_builder.push_condition("tx_height = $?");
            query_builder.query.push_bind(tx_height);
        }
        if let Some(key) = &query.key {
            query_builder.push_condition("key = ");
            query_builder.query.push_bind(&key.0);
        }
        if let Some(offset) = query.offset {
            query_builder.push_condition("offset = ");
            query_builder.query.push_bind(offset);
        }

        // TODO: pagination and sorting.

        let query = query_builder.query.build_query_as();
        Ok(query.fetch_all(&self.pool).await?)
    }

    pub async fn get_blocks(&self, query: &m::BlocksQuery) -> anyhow::Result<Vec<Value>> {
        let mut query_builder =
            WhereClausesBuilder::new(QueryBuilder::new("SELECT blob FROM blocks"));

        // Filtering
        if let Some(hash) = &query.hash {
            query_builder.push_condition("blob->>'hash' = ");
            query_builder.query.push_bind(hash.to_string());
        }
        if let Some(height) = query.height {
            query_builder.push_condition("blob->>'number' = ");
            query_builder.query.push_bind(height.to_string());
        }
        if let Some(parent_hash) = &query.parent_hash {
            query_builder.push_condition("blob->>'parentHash' = ");
            query_builder.query.push_bind(parent_hash.to_string());
        }

        // Pagination
        // TODO

        // Sorting
        query_builder.order_by(&query.sorting.map_to_string(|by| match by {
            m::BlocksQuerySortBy::Height => "(blob->>'number')::bigint",
            m::BlocksQuerySortBy::Timestamp => "blob->>'timestamp'",
        }));

        let query = query_builder.query.build_query_as();
        let rows: Vec<(Value,)> = query.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|v| v.0).collect())
    }

    pub async fn get_transactions(
        &self,
        query: &m::TransactionsQuery,
    ) -> anyhow::Result<Vec<Value>> {
        let mut query_builder =
            WhereClausesBuilder::new(QueryBuilder::new("SELECT blob FROM transactions"));

        // Filtering
        if let Some(filter) = &query.filter {
            match filter {
                m::TransactionsQueryFilter::Batch(batch_id, batch_txs_offset) => {
                    query_builder.push_condition("blob->>'batch_id' = ");
                    query_builder.query.push_bind(batch_id.to_string());
                }
                m::TransactionsQueryFilter::Hash(hash) => {
                    query_builder.push_condition("blob->>'tx_hash' = ");
                    query_builder.query.push_bind(hash.to_string());
                }
                m::TransactionsQueryFilter::Number(num) => {
                    query_builder.push_condition("blob->>'tx_number' = ");
                    query_builder.query.push_bind(num.to_string());
                }
            }
        }

        // Pagination
        // TODO

        // Sorting
        query_builder.order_by(
            &query
                .sorting
                .map_to_string(|m::TransactionsQuerySortBy::Id| "id"),
        );

        let query = query_builder.query.build_query_as();
        let rows: Vec<(Value,)> = query.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|v| v.0).collect())
    }
}

/// Write operations.
impl Db {
    pub async fn upsert_blocks(&self, blocks: &[&Value]) -> anyhow::Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }

        let mut query = QueryBuilder::new("INSERT INTO blocks (blob) ");

        query.push_values(blocks, |mut builder, block| {
            builder.push_bind(block);
        });
        query.push(" ON CONFLICT ((blob->>'hash')) DO UPDATE SET blob = EXCLUDED.blob");

        query.build().execute(&self.pool).await?;
        Ok(())
    }

    pub async fn upsert_transactions(&self, txs: &[Value]) -> anyhow::Result<()> {
        if txs.is_empty() {
            return Ok(());
        }

        let mut query = QueryBuilder::new("INSERT INTO transactions (blob) ");

        query.push_values(txs, |mut builder, tx| {
            builder.push_bind(tx);
        });
        query.push(" ON CONFLICT ((blob->>'tx_hash')) DO UPDATE SET blob = EXCLUDED.blob");

        query.build().execute(&self.pool).await?;
        Ok(())
    }

    pub async fn upsert_events(&self, events: &[m::Event]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut query = QueryBuilder::new("INSERT INTO events (id, key, value) ");

        query.push_values(events, |mut builder, event| {
            builder.push_bind(event.id);
            builder.push_bind(&event.key);
            builder.push_bind(&event.value);
        });
        query.push(" ON CONFLICT ((id)) DO UPDATE SET value = EXCLUDED.value");

        query.build().execute(&self.pool).await?;
        Ok(())
    }
}

/// A wrapper around [`sqlx::QueryBuilder`] which adds some custom functionality
/// on top of it:
///
/// - Syntactically correct `WHERE` clauses.
/// - Type-safe `ORDER BY` clauses.
/// - TODO: cursor-based pagination.
struct WhereClausesBuilder<'a> {
    query: QueryBuilder<'a, Postgres>,
    where_used_already: bool,
}

impl<'a> WhereClausesBuilder<'a> {
    fn new(query: QueryBuilder<'a, Postgres>) -> Self {
        Self {
            query,
            where_used_already: false,
        }
    }

    fn push_condition(&mut self, condition: &str) {
        if self.where_used_already {
            self.query.push(" AND ");
        } else {
            self.query.push(" WHERE ");
            self.where_used_already = true;
        }
        self.query.push(condition);
    }

    fn order_by(&mut self, sorting: &m::SortingQuery<&str>) {
        self.query.push(" ORDER BY ");
        self.query.push(sorting.by);
        self.query.push(" ");
        self.query.push(match sorting.direction {
            m::SortingQueryDirection::Ascending => "ASC",
            m::SortingQueryDirection::Descending => "DESC",
        });
    }
}
