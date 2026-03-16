# Database Security

## DO

- **Use parameterized queries in every language.** Never concatenate user input into SQL strings.
  ```js
  // Node (pg)
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  ```
  ```python
  # Python (psycopg2)
  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
  ```
  ```rust
  // Rust (sqlx)
  let user = sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)
      .fetch_one(&pool).await?;
  ```
  ```go
  // Go (database/sql)
  row := db.QueryRow("SELECT * FROM users WHERE id = $1", userID)
  ```
  ```java
  // Java (JDBC)
  PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
  ps.setInt(1, userId);
  ```
- **Create dedicated DB users per service** with least privilege. The web app user gets SELECT/INSERT/UPDATE on specific tables — never SUPERUSER, CREATEDB, or full schema access.
  ```sql
  CREATE USER webapp_user WITH PASSWORD 'strong_random_password';
  GRANT SELECT, INSERT, UPDATE ON users, orders TO webapp_user;
  -- No DELETE, no DDL, no access to admin tables
  ```
- **Encrypt connections with TLS** — set `sslmode=require` (Postgres) or `--require-secure-transport` (MySQL). Verify the server certificate in production (`sslmode=verify-full`).
- **Change all default credentials immediately** — `postgres/postgres`, `root/root`, `sa/sa` are the first things attackers try.
- **Encrypt backups at rest** using AES-256. Store encryption keys separately from the backups. Test restore procedures regularly.
- **Enable query logging for sensitive operations** (DDL changes, DELETE, permission grants) to a tamper-evident audit log. Don't log full query parameters if they contain PII — log parameterized queries with placeholders.
- **Restrict network access** — DB should only accept connections from known application hosts. No public internet access, ever. Use private subnets and security groups.

## DON'T

- Concatenate strings to build SQL: `"SELECT * FROM users WHERE name = '" + name + "'"` — this is SQL injection.
- Use ORM raw query methods without parameterization: `sequelize.query("SELECT * FROM users WHERE id = " + id)` — ORMs don't auto-parameterize raw queries.
- Run applications as the database superuser (e.g., `postgres`, `root`).
- Leave default ports (5432, 3306, 27017) exposed to the internet.
- Store database connection strings with credentials in version control.
- Disable TLS for database connections "because it's on the same network" — lateral movement after a breach exploits this.
- Use shared credentials across environments — production DB credentials must never appear in dev or staging configs.

## Common AI Mistakes

- Generating raw SQL with string interpolation: `` `SELECT * FROM ${table} WHERE id = ${id}` `` — both the table name and ID are injection vectors.
- Using connection strings with `sslmode=disable` in example code that gets copy-pasted to production.
- Creating a single DB user with full permissions "for simplicity."
- Suggesting `mongoose.connect('mongodb://localhost/mydb')` without authentication — MongoDB defaults to no auth.
- Providing backup scripts that store unencrypted dumps in world-readable directories.
