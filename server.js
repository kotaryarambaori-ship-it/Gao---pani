// Gaon Pani Sewa - Node.js backend (koi npm package nahi chahiye)
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

// ---------- settings (Render ke Environment Variables se) ----------
const PORT = process.env.PORT || 5000;
const ADMIN_KEY = process.env.ADMIN_KEY || ""; // panchayat ka password (zaroori)
const GAON_NAME = process.env.GAON_NAME || ""; // gaon ka naam
const HELPLINE = (process.env.HELPLINE || "").replace(/[^\d+]/g, ""); // call button ka number
const NOTIFY_EMAIL = process.env.NOTIFY_EMAIL || ""; // adhikari ka email, kai ho to comma se
const BREVO_API_KEY = process.env.BREVO_API_KEY || "";
const SENDER_EMAIL = process.env.SENDER_EMAIL || "";
const SITE_URL = (process.env.SITE_URL || "").replace(/\/$/, "");
if (!ADMIN_KEY) console.warn("ADMIN_KEY set nahi hai: Panchayat login band rahega.");

const UPLOADS = path.join(__dirname, "uploads");
const STATIC = path.join(__dirname, "static");
fs.mkdirSync(UPLOADS, { recursive: true });

const TYPES = ["handpump", "no_water", "dirty_water"];
const STATUSES = ["naya", "sarkar_ko_bheji", "kaam_chalu", "theek_hua"];
const TANKER_STATUSES = ["baaki", "raste_mein", "aa_gaya"];
const LABEL = { handpump: "Handpump kharab", no_water: "Pani nahi aa raha", dirty_water: "Pani ganda hai" };
const MAX_BODY = 3 * 1024 * 1024; // 3 MB

// ---------- database ----------
const db = new DatabaseSync(process.env.DB_PATH || path.join(__dirname, "pani.db"));
db.exec(`
  CREATE TABLE IF NOT EXISTS complaints(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    mohalla TEXT NOT NULL,
    note TEXT DEFAULT '',
    photo TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'naya',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS tankers(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mohalla TEXT NOT NULL,
    time TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'baaki'
  );
  CREATE TABLE IF NOT EXISTS readings(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    value INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);
for (const [col, def] of [["token", "TEXT"], ["reply", "TEXT DEFAULT ''"], ["resolved_at", "TEXT"]]) {
  try { db.exec(`ALTER TABLE complaints ADD COLUMN ${col} ${def}`); } catch { /* pehle se hai */ }
}
db.exec("UPDATE complaints SET token = lower(hex(randomblob(8))) WHERE token IS NULL OR token = ''");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_token ON complaints(token)");
if (db.prepare("SELECT COUNT(*) AS c FROM tankers").get().c === 0) {
  const ins = db.prepare("INSERT INTO tankers(mohalla) VALUES (?)");
  for (let i = 1; i <= 4; i++) ins.run(`Mohalla ${i}`);
}
const get = (sql, ...a) => db.prepare(sql).get(...a);
const all = (sql, ...a) => db.prepare(sql).all(...a);

// ---------- helpers ----------
const SEC = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'self'; img-src 'self' data: blob:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'",
};
function send(res, code, data, type = "application/json", extra = {}) {
  const json = type === "application/json";
  res.writeHead(code, { "Content-Type": type, ...SEC, ...(json ? { "Cache-Control": "no-store" } : {}), ...extra });
  res.end(json ? JSON.stringify(data) : data);
}
const fail = (res, code, err) => send(res, code, { error: err });

const clientIp = (req) =>
  (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "?";

// spam rok: ek IP se kitni baar
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  let h = hits.get(key);
  if (!h || h.reset < now) { h = { n: 0, reset: now + windowMs }; hits.set(key, h); }
  h.n++;
  return h.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, h] of hits) if (h.reset < n) hits.delete(k); }, 600000).unref();

// password rok: 5 galat koshish ke baad 15 minute band
const fails = new Map();
const LOCK_MS = 15 * 60 * 1000;
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
function adminState(req) {
  const key = req.headers["x-admin-key"];
  if (!key) return "no";
  const ip = clientIp(req), now = Date.now();
  let f = fails.get(ip);
  if (f && now - f.last > LOCK_MS) { fails.delete(ip); f = undefined; }
  if (f && f.n >= 5) return "locked";
  if (ADMIN_KEY && crypto.timingSafeEqual(sha(key), sha(ADMIN_KEY))) { fails.delete(ip); return "ok"; }
  fails.set(ip, { n: (f ? f.n : 0) + 1, last: now });
  return "no";
}
function requireAdmin(req, res) {
  const s = adminState(req);
  if (s === "ok") return true;
  if (s === "locked") fail(res, 429, "locked"); else fail(res, 403, "bad_pass");
  return false;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject({ code: 413, err: "too_big" }); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString() || "{}")); }
      catch { reject({ code: 400, err: "bad_data" }); }
    });
    req.on("error", () => reject({ code: 400, err: "bad_data" }));
  });
}

function savePhoto(dataUrl) {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || "");
  if (!m) throw { code: 400, err: "bad_photo" };
  const name = crypto.randomBytes(16).toString("hex") + "." + (m[1] === "jpeg" ? "jpg" : m[1]);
  fs.writeFileSync(path.join(UPLOADS, name), Buffer.from(m[2], "base64"));
  return name;
}

async function notifyOfficer(id, c, photo) {
  const to = NOTIFY_EMAIL.split(",").map((e) => e.trim()).filter(Boolean).map((email) => ({ email }));
  if (!to.length || !BREVO_API_KEY || !SENDER_EMAIL) return;
  const lines = ["Gaon se pani ki nayi shikayat aayi hai."];
  if (GAON_NAME) lines.push(`Gaon: ${GAON_NAME}`);
  lines.push(`Shikayat no.: ${id}`, `Samasya: ${LABEL[c.type]}`, `Mohalla: ${c.mohalla}`);
  if (c.note) lines.push(`Vivaran: ${c.note}`);
  if (photo && SITE_URL) lines.push(`Photo: ${SITE_URL}/uploads/${photo}`);
  lines.push("", "Kripya jaldi karywahi karein.");
  try {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        sender: { name: "Gaon Pani Sewa", email: SENDER_EMAIL },
        to,
        subject: `Pani shikayat #${id}: ${LABEL[c.type]} - ${c.mohalla}`,
        textContent: lines.join("\n"),
      }),
    });
    if (r.ok) db.prepare("UPDATE complaints SET status='sarkar_ko_bheji' WHERE id=? AND status='naya'").run(id);
    else console.error("Email nahi gaya, code:", r.status);
  } catch (e) {
    console.error("Email error:", e.message);
  }
}

const MIME = { jpg: "image/jpeg", png: "image/png", webp: "image/webp" };
const PUBLIC_COLS = "token, type, mohalla, note, photo, status, reply, created_at, resolved_at";

// ---------- routes ----------
async function handle(req, res) {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const m = req.method;
  let match;

  if (m === "GET" && p === "/") {
    return send(res, 200, fs.readFileSync(path.join(STATIC, "index.html")), "text/html; charset=utf-8");
  }
  if (m === "GET" && p === "/api/config") return send(res, 200, { gaon: GAON_NAME, helpline: HELPLINE });

  if (m === "GET" && (match = /^\/uploads\/([a-f0-9]{32}\.(jpg|png|webp))$/.exec(p))) {
    const file = path.join(UPLOADS, match[1]);
    if (!fs.existsSync(file)) return fail(res, 404, "not_found");
    return send(res, 200, fs.readFileSync(file), MIME[match[2]], { "Cache-Control": "public, max-age=86400" });
  }

  // ----- tankers / mohalla -----
  if (m === "GET" && p === "/api/tankers") return send(res, 200, all("SELECT * FROM tankers ORDER BY id"));

  if (m === "POST" && p === "/api/tankers") {
    if (!requireAdmin(req, res)) return;
    const b = await readJson(req);
    const name = String(b.name || "").trim().slice(0, 50);
    if (!name) return fail(res, 400, "bad_data");
    if (get("SELECT COUNT(*) AS c FROM tankers").c >= 30) return fail(res, 400, "bad_data");
    if (get("SELECT 1 AS x FROM tankers WHERE mohalla=?", name)) return fail(res, 409, "dup");
    db.prepare("INSERT INTO tankers(mohalla) VALUES (?)").run(name);
    return send(res, 201, { ok: true });
  }

  if ((m === "PUT" || m === "DELETE") && (match = /^\/api\/tankers\/(\d+)$/.exec(p))) {
    if (!requireAdmin(req, res)) return;
    const id = Number(match[1]);
    const row = get("SELECT * FROM tankers WHERE id=?", id);
    if (!row) return fail(res, 404, "not_found");
    if (m === "DELETE") {
      if (get("SELECT COUNT(*) AS c FROM tankers").c <= 1) return fail(res, 400, "bad_data");
      db.prepare("DELETE FROM tankers WHERE id=?").run(id);
      return send(res, 200, { ok: true });
    }
    const b = await readJson(req);
    if (!TANKER_STATUSES.includes(b.status)) return fail(res, 400, "bad_data");
    const name = b.name === undefined ? row.mohalla : String(b.name).trim().slice(0, 50);
    if (!name) return fail(res, 400, "bad_data");
    if (name !== row.mohalla) {
      if (get("SELECT 1 AS x FROM tankers WHERE mohalla=? AND id!=?", name, id)) return fail(res, 409, "dup");
      db.prepare("UPDATE complaints SET mohalla=? WHERE mohalla=?").run(name, row.mohalla);
    }
    db.prepare("UPDATE tankers SET mohalla=?, time=?, status=? WHERE id=?").run(
      name, String(b.time || "").slice(0, 30), b.status, id
    );
    return send(res, 200, { ok: true });
  }

  // ----- complaints -----
  if (m === "POST" && p === "/api/complaints") {
    if (limited("c:" + clientIp(req), 5, 3600 * 1000)) return fail(res, 429, "too_many");
    const b = await readJson(req);
    const mohalla = String(b.mohalla || "").trim().slice(0, 50);
    const note = String(b.note || "").trim().slice(0, 500);
    if (!TYPES.includes(b.type)) return fail(res, 400, "pick_type");
    if (!mohalla || !get("SELECT 1 AS x FROM tankers WHERE mohalla=?", mohalla)) return fail(res, 400, "pick_mohalla");
    const photo = b.photo ? savePhoto(b.photo) : "";
    const token = crypto.randomBytes(8).toString("hex");
    const r = db
      .prepare("INSERT INTO complaints(type, mohalla, note, photo, token) VALUES (?,?,?,?,?)")
      .run(b.type, mohalla, note, photo, token);
    notifyOfficer(Number(r.lastInsertRowid), { type: b.type, mohalla, note }, photo);
    return send(res, 201, { token });
  }

  if (m === "GET" && p === "/api/complaints") {
    const s = adminState(req);
    if (s === "locked") return fail(res, 429, "locked");
    if (s === "ok") {
      return send(res, 200, all(`SELECT c.*, (SELECT COUNT(*) FROM complaints d
        WHERE d.mohalla=c.mohalla AND d.type=c.type AND d.status!='theek_hua') AS similar
        FROM complaints c ORDER BY c.id DESC LIMIT 500`));
    }
    const tokens = (url.searchParams.get("tokens") || "")
      .split(",").filter((x) => /^[a-f0-9]{16}$/.test(x)).slice(0, 50);
    if (!tokens.length) return send(res, 200, []);
    const q = tokens.map(() => "?").join(",");
    return send(res, 200, all(`SELECT ${PUBLIC_COLS} FROM complaints WHERE token IN (${q}) ORDER BY id DESC`, ...tokens));
  }

  if (m === "PATCH" && (match = /^\/api\/complaints\/(\d+)$/.exec(p))) {
    if (!requireAdmin(req, res)) return;
    const id = Number(match[1]);
    if (!get("SELECT 1 AS x FROM complaints WHERE id=?", id)) return fail(res, 404, "not_found");
    const b = await readJson(req);
    if (b.status !== undefined) {
      if (!STATUSES.includes(b.status)) return fail(res, 400, "bad_data");
      db.prepare(`UPDATE complaints SET status=?,
        resolved_at = CASE WHEN ?='theek_hua' THEN COALESCE(resolved_at, datetime('now')) ELSE NULL END
        WHERE id=?`).run(b.status, b.status, id);
    }
    if (b.reply !== undefined) {
      db.prepare("UPDATE complaints SET reply=? WHERE id=?").run(String(b.reply).trim().slice(0, 300), id);
    }
    return send(res, 200, { ok: true });
  }

  // ----- pani level / quality -----
  if (m === "GET" && p === "/api/readings") {
    return send(res, 200, all(`SELECT id, kind, source, value, created_at FROM readings
      WHERE created_at >= datetime('now','-60 days') ORDER BY id DESC LIMIT 400`));
  }
  if (m === "POST" && p === "/api/readings") {
    if (!requireAdmin(req, res)) return;
    const b = await readJson(req);
    const source = String(b.source || "").trim().slice(0, 40);
    const value = Number(b.value);
    const max = b.kind === "level" ? 100 : 5000;
    if (!["level", "tds"].includes(b.kind) || !source || !Number.isInteger(value) || value < 0 || value > max) {
      return fail(res, 400, "bad_data");
    }
    db.prepare("INSERT INTO readings(kind, source, value) VALUES (?,?,?)").run(b.kind, source, value);
    return send(res, 201, { ok: true });
  }
  if (m === "DELETE" && (match = /^\/api\/readings\/(\d+)$/.exec(p))) {
    if (!requireAdmin(req, res)) return;
    db.prepare("DELETE FROM readings WHERE id=?").run(Number(match[1]));
    return send(res, 200, { ok: true });
  }

  // ----- report -----
  if (m === "GET" && p === "/api/report") {
    const avg = get(`SELECT AVG(julianday(resolved_at)-julianday(created_at)) AS d
      FROM complaints WHERE resolved_at IS NOT NULL`).d;
    return send(res, 200, {
      total: get("SELECT COUNT(*) AS c FROM complaints").c,
      month: get("SELECT COUNT(*) AS c FROM complaints WHERE strftime('%Y-%m',created_at)=strftime('%Y-%m','now')").c,
      done: get("SELECT COUNT(*) AS c FROM complaints WHERE status='theek_hua'").c,
      old: get(`SELECT COUNT(*) AS c FROM complaints WHERE status!='theek_hua'
        AND julianday('now')-julianday(created_at)>7`).c,
      avgDays: avg === null ? null : Math.round(avg * 10) / 10,
      byMohalla: all(`SELECT mohalla, COUNT(*) AS total, SUM(status!='theek_hua') AS pending
        FROM complaints GROUP BY mohalla ORDER BY pending DESC, total DESC`),
      byType: all("SELECT type, COUNT(*) AS c FROM complaints GROUP BY type ORDER BY c DESC"),
    });
  }

  fail(res, 404, "not_found");
}

http
  .createServer((req, res) => {
    handle(req, res).catch((e) => {
      if (e && e.code && e.err) return fail(res, e.code, e.err);
      console.error(e);
      fail(res, 500, "server");
    });
  })
  .listen(PORT, "0.0.0.0", () => console.log(`Chal raha hai: http://localhost:${PORT}`));
