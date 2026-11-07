// Gaon Pani Sewa - Node.js backend (koi npm package nahi chahiye)
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const PORT = process.env.PORT || 5000;
const ADMIN_KEY = process.env.ADMIN_KEY || "change-me"; // panchayat ka password
const UPLOADS = path.join(__dirname, "uploads");
const STATIC = path.join(__dirname, "static");
fs.mkdirSync(UPLOADS, { recursive: true });

const TYPES = ["handpump", "no_water", "dirty_water"];
const STATUSES = ["naya", "kaam_chalu", "theek_hua"];
const TANKER_STATUSES = ["baaki", "raste_mein", "aa_gaya"];
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
`);
if (db.prepare("SELECT COUNT(*) AS c FROM tankers").get().c === 0) {
  const ins = db.prepare("INSERT INTO tankers(mohalla) VALUES (?)");
  for (let i = 1; i <= 4; i++) ins.run(`Mohalla ${i}`);
}

// ---------- helpers ----------
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const isAdmin = (req) =>
  crypto.timingSafeEqual(sha(req.headers["x-admin-key"] || ""), sha(ADMIN_KEY));

function send(res, code, data, type = "application/json") {
  res.writeHead(code, { "Content-Type": type, "X-Content-Type-Options": "nosniff" });
  res.end(type === "application/json" ? JSON.stringify(data) : data);
}
const fail = (res, code, msg) => send(res, code, { error: msg });

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject({ code: 413, msg: "Photo bahut badi hai" });
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString() || "{}"));
      } catch {
        reject({ code: 400, msg: "Galat data" });
      }
    });
    req.on("error", () => reject({ code: 400, msg: "Galat data" }));
  });
}

function savePhoto(dataUrl) {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || "");
  if (!m) throw { code: 400, msg: "Sirf jpg, png ya webp photo" };
  const name = crypto.randomBytes(16).toString("hex") + "." + (m[1] === "jpeg" ? "jpg" : m[1]);
  fs.writeFileSync(path.join(UPLOADS, name), Buffer.from(m[2], "base64"));
  return name;
}

const MIME = { jpg: "image/jpeg", png: "image/png", webp: "image/webp" };

// ---------- routes ----------
async function handle(req, res) {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const m = req.method;
  let match;

  if (m === "GET" && p === "/") {
    return send(res, 200, fs.readFileSync(path.join(STATIC, "index.html")), "text/html; charset=utf-8");
  }

  if (m === "GET" && (match = /^\/uploads\/([a-f0-9]{32}\.(jpg|png|webp))$/.exec(p))) {
    const file = path.join(UPLOADS, match[1]);
    if (!fs.existsSync(file)) return fail(res, 404, "Nahi mila");
    return send(res, 200, fs.readFileSync(file), MIME[match[2]]);
  }

  if (m === "GET" && p === "/api/tankers") {
    return send(res, 200, db.prepare("SELECT * FROM tankers ORDER BY id").all());
  }

  if (m === "PUT" && (match = /^\/api\/tankers\/(\d+)$/.exec(p))) {
    if (!isAdmin(req)) return fail(res, 403, "Panchayat password galat hai");
    const b = await readJson(req);
    if (!TANKER_STATUSES.includes(b.status)) return fail(res, 400, "Galat status");
    db.prepare("UPDATE tankers SET time=?, status=? WHERE id=?").run(
      String(b.time || "").slice(0, 30), b.status, Number(match[1])
    );
    return send(res, 200, { ok: true });
  }

  if (m === "POST" && p === "/api/complaints") {
    const b = await readJson(req);
    const mohalla = String(b.mohalla || "").trim().slice(0, 50);
    const note = String(b.note || "").trim().slice(0, 500);
    if (!TYPES.includes(b.type)) return fail(res, 400, "Problem chuno");
    if (!mohalla) return fail(res, 400, "Mohalla chuno");
    const photo = b.photo ? savePhoto(b.photo) : "";
    const r = db
      .prepare("INSERT INTO complaints(type, mohalla, note, photo) VALUES (?,?,?,?)")
      .run(b.type, mohalla, note, photo);
    return send(res, 201, { id: Number(r.lastInsertRowid) });
  }

  if (m === "GET" && p === "/api/complaints") {
    if (isAdmin(req)) {
      return send(res, 200, db.prepare("SELECT * FROM complaints ORDER BY id DESC").all());
    }
    const ids = (url.searchParams.get("ids") || "")
      .split(",").filter((x) => /^\d+$/.test(x)).slice(0, 50).map(Number);
    if (!ids.length) return send(res, 200, []);
    const q = ids.map(() => "?").join(",");
    return send(res, 200, db.prepare(`SELECT * FROM complaints WHERE id IN (${q}) ORDER BY id DESC`).all(...ids));
  }

  if (m === "PATCH" && (match = /^\/api\/complaints\/(\d+)$/.exec(p))) {
    if (!isAdmin(req)) return fail(res, 403, "Panchayat password galat hai");
    const b = await readJson(req);
    if (!STATUSES.includes(b.status)) return fail(res, 400, "Galat status");
    db.prepare("UPDATE complaints SET status=? WHERE id=?").run(b.status, Number(match[1]));
    return send(res, 200, { ok: true });
  }

  fail(res, 404, "Nahi mila");
}

http
  .createServer((req, res) => {
    handle(req, res).catch((e) => {
      if (e && e.code && e.msg) return fail(res, e.code, e.msg);
      console.error(e);
      fail(res, 500, "Server mein gadbad hui");
    });
  })
  .listen(PORT, "0.0.0.0", () => console.log(`Chal raha hai: http://localhost:${PORT}`));
