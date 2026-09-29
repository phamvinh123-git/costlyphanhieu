const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Falls back to a random secret if JWT_SECRET isn't set — tokens just won't
// survive a server restart in that case (everyone has to log in again).
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const TOKEN_COOKIE = "costly_token";
const ALLOWED_COLLECTIONS = new Set(["ingredients", "batches", "recipes"]);
// Legacy data (from before accounts were per-shop) belongs to this tenant —
// it's the real shop that was already using the app.
const LEGACY_TENANT = process.env.OWNER_USERNAME || "chuquan";

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS documents (
      tenant TEXT NOT NULL,
      collection TEXT NOT NULL,
      id TEXT NOT NULL,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant, collection, id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'owner')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await pool.query(`ALTER TABLE app_users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now()`);
  // migration: drop the old staff-only 'nhanvien' account (role='user') BEFORE
  // tightening the constraint, or the constraint add fails on that leftover row.
  await pool.query(`ALTER TABLE app_users DROP CONSTRAINT IF EXISTS app_users_role_check`);
  await pool.query(`DELETE FROM app_users WHERE role NOT IN ('admin', 'owner')`);
  await pool.query(`ALTER TABLE app_users ADD CONSTRAINT app_users_role_check CHECK (role IN ('admin', 'owner'))`);

  // migration: data used to be shared globally (no tenant column at all).
  // Give every pre-existing row to the legacy tenant BEFORE tightening the
  // primary key, then rebuild the key as (tenant, collection, id).
  await pool.query(`ALTER TABLE documents ADD COLUMN IF NOT EXISTS tenant TEXT`);
  await pool.query(`UPDATE documents SET tenant=$1 WHERE tenant IS NULL`, [LEGACY_TENANT]);
  await pool.query(`ALTER TABLE documents ALTER COLUMN tenant SET NOT NULL`);
  await pool.query(`ALTER TABLE documents DROP CONSTRAINT IF EXISTS documents_pkey`);
  await pool.query(`ALTER TABLE documents ADD CONSTRAINT documents_pkey PRIMARY KEY (tenant, collection, id)`);
}

// Seeds the legacy tenant's data from seed.json, but only if it has nothing
// yet (a brand-new deployment). A freshly created owner account always
// starts with zero documents — nothing seeds their tenant automatically.
async function maybeSeedLegacyTenant() {
  const { rows } = await pool.query("SELECT COUNT(*)::int AS c FROM documents WHERE tenant=$1", [LEGACY_TENANT]);
  if (rows[0].c > 0) return;
  const seedPath = path.join(__dirname, "seed.json");
  if (!fs.existsSync(seedPath)) return;
  const seed = JSON.parse(fs.readFileSync(seedPath, "utf8"));
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const collection of Object.keys(seed)) {
      for (const doc of seed[collection]) {
        await client.query(
          "INSERT INTO documents (tenant, collection, id, data) VALUES ($1,$2,$3,$4) ON CONFLICT (tenant,collection,id) DO NOTHING",
          [LEGACY_TENANT, collection, doc.id, doc.data]
        );
      }
    }
    await client.query("COMMIT");
    console.log("Seeded initial data from seed.json into tenant " + LEGACY_TENANT);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Seed failed", e);
  } finally {
    client.release();
  }
}

// Creates the two built-in accounts from env vars the first time the server
// boots. Only fills in accounts that don't exist yet — once someone changes
// their password via the app, a redeploy/restart must never overwrite it.
// Both roles get full read/write access — they're just two separate logins
// (e.g. one for the developer, one for the shop owner), not a permission tier.
async function syncSeedUsers() {
  const accounts = [
    { username: process.env.ADMIN_USERNAME || "admin", password: process.env.ADMIN_PASSWORD, role: "admin" },
    { username: process.env.OWNER_USERNAME || "chuquan", password: process.env.OWNER_PASSWORD, role: "owner" },
  ];
  for (const acc of accounts) {
    if (!acc.password) continue;
    const hash = await bcrypt.hash(acc.password, 10);
    await pool.query(
      `INSERT INTO app_users (username, password_hash, role) VALUES ($1,$2,$3)
       ON CONFLICT (username) DO NOTHING`,
      [acc.username, hash, acc.role]
    );
  }
}

function signToken(user) {
  return jwt.sign({ sub: user.username, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
}

function authRequired(req, res, next) {
  const token = req.cookies[TOKEN_COOKIE];
  if (!token) return res.status(401).json({ error: "unauthenticated" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.clearCookie(TOKEN_COOKIE);
    return res.status(401).json({ error: "unauthenticated" });
  }
}

const cookieOpts = {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production" || !!process.env.RENDER,
  maxAge: 30 * 24 * 60 * 60 * 1000,
};

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "missing credentials" });
  try {
    const { rows } = await pool.query("SELECT * FROM app_users WHERE username=$1", [username]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "invalid credentials" });
    }
    const token = signToken(user);
    res.cookie(TOKEN_COOKIE, token, cookieOpts);
    res.json({ username: user.username, role: user.role });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie(TOKEN_COOKIE);
  res.json({ ok: true });
});

app.get("/api/auth/me", authRequired, (req, res) => {
  res.json({ username: req.user.sub, role: req.user.role });
});

app.post("/api/auth/change-password", authRequired, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "missing fields" });
  if (newPassword.length < 6) return res.status(400).json({ error: "password too short" });
  try {
    const { rows } = await pool.query("SELECT * FROM app_users WHERE username=$1", [req.user.sub]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(currentPassword, user.password_hash))) {
      return res.status(401).json({ error: "wrong current password" });
    }
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE app_users SET password_hash=$1 WHERE username=$2", [hash, user.username]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "forbidden" });
  next();
}

const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

// Anyone signed in can add a new login. A non-admin can only ever create a
// fellow "owner" account — never grant admin rights to someone else.
app.post("/api/users", authRequired, async (req, res) => {
  let { username, password, role } = req.body || {};
  username = (username || "").trim();
  if (!USERNAME_RE.test(username)) {
    return res.status(400).json({ error: "username must be 3-32 letters/digits/._-" });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: "password too short" });
  }
  if (req.user.role !== "admin" || (role !== "admin" && role !== "owner")) {
    role = "owner";
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO app_users (username, password_hash, role) VALUES ($1,$2,$3)",
      [username, hash, role]
    );
    res.json({ username, role });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "username already exists" });
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// Everything below is admin-only account management — list, reset a
// password, change a role, or remove an account.
app.get("/api/users", authRequired, adminOnly, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT username, role, created_at FROM app_users ORDER BY created_at"
  );
  res.json(rows);
});

app.patch("/api/users/:username", authRequired, adminOnly, async (req, res) => {
  const { username } = req.params;
  const { role, newPassword } = req.body || {};
  try {
    const { rows } = await pool.query("SELECT * FROM app_users WHERE username=$1", [username]);
    const target = rows[0];
    if (!target) return res.status(404).json({ error: "not found" });

    if (role && role !== target.role) {
      if (role !== "admin" && role !== "owner") return res.status(400).json({ error: "invalid role" });
      if (target.role === "admin") {
        const { rows: admins } = await pool.query("SELECT COUNT(*)::int AS c FROM app_users WHERE role='admin'");
        if (admins[0].c <= 1) return res.status(400).json({ error: "cannot demote the last admin" });
      }
      await pool.query("UPDATE app_users SET role=$1 WHERE username=$2", [role, username]);
    }
    if (newPassword) {
      if (newPassword.length < 6) return res.status(400).json({ error: "password too short" });
      const hash = await bcrypt.hash(newPassword, 10);
      await pool.query("UPDATE app_users SET password_hash=$1 WHERE username=$2", [hash, username]);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

app.delete("/api/users/:username", authRequired, adminOnly, async (req, res) => {
  const { username } = req.params;
  if (username === req.user.sub) return res.status(400).json({ error: "cannot delete your own account" });
  try {
    const { rows } = await pool.query("SELECT * FROM app_users WHERE username=$1", [username]);
    const target = rows[0];
    if (!target) return res.status(404).json({ error: "not found" });
    if (target.role === "admin") {
      const { rows: admins } = await pool.query("SELECT COUNT(*)::int AS c FROM app_users WHERE role='admin'");
      if (admins[0].c <= 1) return res.status(400).json({ error: "cannot delete the last admin" });
    }
    await pool.query("DELETE FROM app_users WHERE username=$1", [username]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

function checkCollection(req, res, next) {
  if (!ALLOWED_COLLECTIONS.has(req.params.collection)) {
    return res.status(404).json({ error: "unknown collection" });
  }
  next();
}

// Every shop's ingredients/batches/recipes are isolated by tenant. An owner
// always operates on their own shop (their username IS the tenant) — the
// server ignores anything else they might pass. Admin isn't a shop of their
// own, so they must say which shop they're viewing via ?tenant=<username>,
// and that username must be a real owner account.
async function resolveTenant(req, res, next) {
  if (req.user.role === "owner") {
    req.tenant = req.user.sub;
    return next();
  }
  const tenant = req.query.tenant;
  if (!tenant) return res.status(400).json({ error: "tenant required" });
  try {
    const { rows } = await pool.query("SELECT 1 FROM app_users WHERE username=$1 AND role='owner'", [tenant]);
    if (!rows.length) return res.status(400).json({ error: "unknown tenant" });
    req.tenant = tenant;
    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
}

app.get("/api/:collection", authRequired, resolveTenant, checkCollection, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, data FROM documents WHERE tenant=$1 AND collection=$2 ORDER BY id",
      [req.tenant, req.params.collection]
    );
    res.json(rows.map((r) => Object.assign({ id: r.id }, r.data)));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

app.put("/api/:collection/:id", authRequired, resolveTenant, checkCollection, async (req, res) => {
  try {
    const data = req.body || {};
    await pool.query(
      `INSERT INTO documents (tenant, collection, id, data, updated_at) VALUES ($1,$2,$3,$4,now())
       ON CONFLICT (tenant,collection,id) DO UPDATE SET data=$4, updated_at=now()`,
      [req.tenant, req.params.collection, req.params.id, data]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

app.delete("/api/:collection/:id", authRequired, resolveTenant, checkCollection, async (req, res) => {
  try {
    await pool.query("DELETE FROM documents WHERE tenant=$1 AND collection=$2 AND id=$3", [
      req.tenant,
      req.params.collection,
      req.params.id,
    ]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;

(async () => {
  try {
    await ensureSchema();
    await maybeSeedLegacyTenant();
    await syncSeedUsers();
  } catch (e) {
    console.error("Startup error", e);
  }
  app.listen(PORT, () => console.log("Cost Ly server listening on " + PORT));
})();
