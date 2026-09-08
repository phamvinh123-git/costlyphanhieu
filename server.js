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

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS documents (
      collection TEXT NOT NULL,
      id TEXT NOT NULL,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (collection, id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'owner'))
    )
  `);
  // migration: the role check used to be ('admin','user') — widen it to allow 'owner',
  // and drop the old staff-only 'nhanvien' account, which no longer has a place.
  await pool.query(`ALTER TABLE app_users DROP CONSTRAINT IF EXISTS app_users_role_check`);
  await pool.query(`ALTER TABLE app_users ADD CONSTRAINT app_users_role_check CHECK (role IN ('admin', 'owner'))`);
  await pool.query(`DELETE FROM app_users WHERE role = 'user'`);
}

async function maybeSeed() {
  const { rows } = await pool.query("SELECT COUNT(*)::int AS c FROM documents");
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
          "INSERT INTO documents (collection, id, data) VALUES ($1,$2,$3) ON CONFLICT (collection,id) DO NOTHING",
          [collection, doc.id, doc.data]
        );
      }
    }
    await client.query("COMMIT");
    console.log("Seeded initial data from seed.json");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Seed failed", e);
  } finally {
    client.release();
  }
}

// Creates/updates the two built-in accounts from env vars on every boot, so
// rotating a password is just: change the env var on Render, redeploy.
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
       ON CONFLICT (username) DO UPDATE SET password_hash=$2, role=$3`,
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

function checkCollection(req, res, next) {
  if (!ALLOWED_COLLECTIONS.has(req.params.collection)) {
    return res.status(404).json({ error: "unknown collection" });
  }
  next();
}

app.get("/api/:collection", authRequired, checkCollection, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, data FROM documents WHERE collection=$1 ORDER BY id",
      [req.params.collection]
    );
    res.json(rows.map((r) => Object.assign({ id: r.id }, r.data)));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

app.put("/api/:collection/:id", authRequired, checkCollection, async (req, res) => {
  try {
    const data = req.body || {};
    await pool.query(
      `INSERT INTO documents (collection, id, data, updated_at) VALUES ($1,$2,$3,now())
       ON CONFLICT (collection,id) DO UPDATE SET data=$3, updated_at=now()`,
      [req.params.collection, req.params.id, data]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

app.delete("/api/:collection/:id", authRequired, checkCollection, async (req, res) => {
  try {
    await pool.query("DELETE FROM documents WHERE collection=$1 AND id=$2", [
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
    await maybeSeed();
    await syncSeedUsers();
  } catch (e) {
    console.error("Startup error", e);
  }
  app.listen(PORT, () => console.log("Cost Ly server listening on " + PORT));
})();
