import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

export async function initDb() {
  await pool.query(`
    create table if not exists verifications (
      user_id    text primary key,
      code       text not null,
      verified   boolean not null default false,
      created_at timestamptz not null default now(),
      expires_at timestamptz not null
    );
    create index if not exists verifications_expires_idx on verifications(expires_at);
  `);
}

export async function upsertCode(userId, code, ttlMinutes) {
  const { rows } = await pool.query(
    `insert into verifications (user_id, code, verified, expires_at)
     values ($1, $2, false, now() + ($3 || ' minutes')::interval)
     on conflict (user_id)
     do update set code = EXCLUDED.code,
                   verified = false,
                   created_at = now(),
                   expires_at = EXCLUDED.expires_at
     returning user_id, code, verified, created_at, expires_at`,
    [userId, code, String(ttlMinutes)]
  );
  return rows[0];
}

export async function verifyCode(userId, code) {
  const { rowCount } = await pool.query(
    `update verifications
       set verified = true
     where user_id = $1
       and code = $2
       and verified = false
       and now() <= expires_at`,
    [userId, code]
  );
  return rowCount > 0;
}

export async function getStatus(userId) {
  const { rows } = await pool.query(
    `select verified, now() <= expires_at as not_expired
       from verifications
      where user_id = $1`,
    [userId]
  );
  if (!rows.length) return { found: false, verified: false, not_expired: false };
  const r = rows[0];
  return { found: true, verified: r.verified, not_expired: r.not_expired };
}

export async function pruneExpired() {
  await pool.query(`delete from verifications where verified = false and now() > expires_at`);
}
