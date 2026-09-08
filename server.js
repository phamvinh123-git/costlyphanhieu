const express = require("express");
const path = require("path");
const fs = require("fs");
const { Pool } = require("pg");

const app = express();
app.use(express.json({ limit: "2mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

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

function checkCollection(req, res, next) {
  if (!ALLOWED_COLLECTIONS.has(req.params.collection)) {
    return res.status(404).json({ error: "unknown collection" });
  }
  next();
}

app.get("/api/:collection", checkCollection, async (req, res) => {
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

app.put("/api/:collection/:id", checkCollection, async (req, res) => {
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

app.delete("/api/:collection/:id", checkCollection, async (req, res) => {
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
  } catch (e) {
    console.error("Startup error", e);
  }
  app.listen(PORT, () => console.log("Cost Ly server listening on " + PORT));
})();
