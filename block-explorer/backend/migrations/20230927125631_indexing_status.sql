CREATE TABLE IF NOT EXISTS indexing_status (
	id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
	chain_head_blob JSONB NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
