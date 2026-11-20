// Drop Chance Forever: the mailbox in the cloud (Cloudflare Worker, free plan).
//
// Players' Companion programs send their drop counts here; this keeps them in a waiting list (D1) until
// Marijan's home server collects them. The home server then deletes what it took, so the cloud never fills
// up. The home server adds everything up and sends the combined file back here, and the Companions download
// it from here, so downloads work while the home PC is off.
//
//   POST /upload          a player's counts (gzip JSON as the body; ID, computer code and version in headers)
//   GET  /data.json       everyone's numbers (the last file the home server sent)
//   GET  /stats           small numbers
//   POST /home/pull       home server: the waiting uploads          (signed)
//   POST /home/ack        home server: delete what it took          (signed)
//   PUT  /home/data       home server: the new combined file        (signed)
//   PUT  /home/bans       home server: the ban list                 (signed)
//
// Signed = the home server signs each request with its own private key (Ed25519). Only its PUBLIC key is
// here (HOME_KEY), so nothing secret is in this code. Internet addresses are never kept: only a scrambled
// code made with a random salt that this Worker made itself and keeps in its database.

const HOME_KEY = ""; // the home server's public key (base64), from https://rucksackforever.duckdns.org/api/drops/homekey

const MAX_BODY = 1000000;        // an upload, gzip (bigger: refused)
const EVERY = 15 * 60;           // one upload per player per 15 minutes
const PER_HOUR = 2000;           // uploads from everyone in an hour
const NEW_IDS_PER_IP = 5;        // new player IDs from one internet address in a day
const PULL_MAX = 25;             // uploads per pull
const PULL_BYTES = 6000000;      // and at most about this much text per pull
const SIG_WINDOW = 300;          // signed requests must be this fresh (seconds)

const ID_RE = /^[0-9a-f]{32}$/;
const PC_RE = /^[0-9a-f]{64}$/;

export default {
  async fetch(req, env, ctx) {
    try {
      return await route(req, env, ctx);
    } catch (e) {
      return json({ error: "Try later." }, 500);
    }
  },
  async scheduled(ev, env, ctx) {
    await ensure(env);
    const hour = Math.floor(Date.now() / 3600000);
    await env.DB.prepare("delete from hits where hour < ?").bind(hour - 48).run();
  },
};

// the tables (made the first time; cheap to ask again)
const SCHEMA = "create table if not exists meta (k text primary key, v text); create table if not exists clients (id text primary key, pc text not null default '', ip text not null default '', app text not null default '', first integer not null, last integer not null, uploads integer not null default 0); create index if not exists clients_ip on clients (ip, first); create table if not exists pending (id text primary key, ver integer not null, pc text not null default '', ip text not null default '', app text not null default '', at integer not null, body text not null); create index if not exists pending_at on pending (at); create table if not exists bans (kind text not null, value text not null, until integer not null default 0, primary key (kind, value)); create table if not exists hits (hour integer primary key, n integer not null);";
let ready = false;
async function ensure(env) {
  if (ready) return;
  for (const q of SCHEMA.split(";")) if (q.trim()) await env.DB.prepare(q).run();
  ready = true;
}

async function route(req, env, ctx) {
  await ensure(env);
  const url = new URL(req.url);
  const p = url.pathname;
  if (p === "/upload" && req.method === "POST") return upload(req, env);
  if ((p === "/data.json" || p === "/api/drops/data.json") && (req.method === "GET" || req.method === "HEAD")) return data(req, env, ctx);
  if (p === "/stats" && req.method === "GET") return stats(env);
  if (p.startsWith("/home/")) return home(req, env, p);
  if (p === "/" || p === "") return new Response("Drop Chance Forever: drop data for WoW Forever. https://rucksackforever.duckdns.org/drops\n", { headers: { "content-type": "text/plain; charset=utf-8" } });
  return json({ error: "Not found." }, 404);
}

function json(o, status = 200, extra = {}) {
  return new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra } });
}
const now = () => Math.floor(Date.now() / 1000);

function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function b64(bytes) {
  let s = "";
  const u = new Uint8Array(bytes);
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

// the salt for internet addresses: random, made once by this Worker, kept in its database
let saltCache = null;
async function salt(env) {
  if (saltCache) return saltCache;
  let r = await env.DB.prepare("select v from meta where k = 'salt'").first();
  if (!r) {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    await env.DB.prepare("insert or ignore into meta (k, v) values ('salt', ?)").bind(hex(b)).run();
    r = await env.DB.prepare("select v from meta where k = 'salt'").first();
  }
  saltCache = r.v;
  return saltCache;
}
async function ipCode(req, env) {
  const ip = req.headers.get("cf-connecting-ip") || "";
  if (!ip) return "";
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode((await salt(env)) + "|" + ip));
  return hex(d).slice(0, 32);
}

// ------------------------------------------------------------------ upload

async function upload(req, env) {
  const id = (req.headers.get("x-dcf-id") || "").toLowerCase();
  let pc = (req.headers.get("x-dcf-pc") || "").toLowerCase();
  const app = (req.headers.get("x-dcf-app") || "").replace(/[^0-9A-Za-z .+-]/g, "").slice(0, 20);
  if (!ID_RE.test(id)) return json({ error: "Bad ID." }, 400);
  if (!PC_RE.test(pc)) pc = "";
  const len = Number(req.headers.get("content-length") || "0");
  if (len > MAX_BODY) return json({ error: "Too big." }, 413);
  const body = new Uint8Array(await req.arrayBuffer());
  if (body.length === 0) return json({ error: "Empty." }, 400);
  if (body.length > MAX_BODY) return json({ error: "Too big." }, 413);
  if (body[0] !== 0x1f || body[1] !== 0x8b) return json({ error: "Send it gzipped." }, 400);

  const t = now();
  const hour = Math.floor(t / 3600);
  const ip = await ipCode(req, env);
  const ok = () => json({ ok: true });

  const banned = await env.DB.prepare(
    "select 1 from bans where ((kind = 'id' and value = ?1) or (kind = 'pc' and value = ?2 and ?2 != '') or (kind = 'ip' and value = ?3 and ?3 != '')) and (until = 0 or until > ?4) limit 1"
  ).bind(id, pc, ip, t).first();
  if (banned) return ok(); // (a banned sender is told the same as everyone)

  const hits = await env.DB.prepare("select n from hits where hour = ?").bind(hour).first();
  if (hits && hits.n >= PER_HOUR) return json({ error: "Busy.", wait: 600 }, 429);

  const cl = await env.DB.prepare("select last from clients where id = ?").bind(id).first();
  if (cl && t - cl.last < EVERY) return json({ error: "Too soon.", wait: EVERY - (t - cl.last) }, 429);
  if (!cl && ip) {
    const n = await env.DB.prepare("select count(*) as n from clients where ip = ? and first > ?").bind(ip, t - 86400).first();
    if (n && n.n >= NEW_IDS_PER_IP) return ok(); // (too many new players from one address today: not kept)
  }

  const text = b64(body);
  await env.DB.batch([
    env.DB.prepare(
      "insert into clients (id, pc, ip, app, first, last, uploads) values (?1, ?2, ?3, ?4, ?5, ?5, 1) " +
        "on conflict (id) do update set pc = ?2, ip = ?3, app = ?4, last = ?5, uploads = uploads + 1"
    ).bind(id, pc, ip, app, t),
    env.DB.prepare(
      "insert into pending (id, ver, pc, ip, app, at, body) values (?1, 1, ?2, ?3, ?4, ?5, ?6) " +
        "on conflict (id) do update set ver = ver + 1, pc = ?2, ip = ?3, app = ?4, at = ?5, body = ?6"
    ).bind(id, pc, ip, app, t, text),
    env.DB.prepare("insert into hits (hour, n) values (?1, 1) on conflict (hour) do update set n = n + 1").bind(hour),
  ]);
  return ok();
}

// ------------------------------------------------------------------ everyone's numbers

async function data(req, env, ctx) {
  const cache = caches.default;
  const key = new Request(new URL("/data.json", req.url).toString());
  const tag = req.headers.get("if-none-match");
  let hit = await cache.match(key);
  if (!hit) {
    const { value, metadata } = await env.DATA.getWithMetadata("data", { type: "arrayBuffer" });
    if (!value) return json({ error: "Not ready yet." }, 503);
    hit = new Response(value, {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "x-dcf-gzip": "1",
        etag: (metadata && metadata.etag) || '"0"',
        "cache-control": "public, max-age=300",
      },
    });
    ctx.waitUntil(cache.put(key, hit.clone()));
  }
  const etag = hit.headers.get("etag");
  const base = { "content-type": "application/json; charset=utf-8", etag, "cache-control": "public, max-age=300", vary: "accept-encoding", "access-control-allow-origin": "*" };
  if (tag && tag === etag) return new Response(null, { status: 304, headers: base });
  if (req.method === "HEAD") return new Response(null, { headers: base });
  const gz = await hit.arrayBuffer();
  if ((req.headers.get("accept-encoding") || "").includes("gzip")) {
    return new Response(gz, { headers: { ...base, "content-encoding": "gzip" }, encodeBody: "manual" });
  }
  const plain = new Response(gz).body.pipeThrough(new DecompressionStream("gzip"));
  return new Response(plain, { headers: base });
}

async function stats(env) {
  const w = await env.DB.prepare("select count(*) as n, coalesce(sum(length(body)), 0) as b from pending").first();
  const c = await env.DB.prepare("select count(*) as n from clients").first();
  const m = await env.DATA.getWithMetadata("data", { type: "stream" });
  return json({ waiting: w.n, waitingKB: Math.round(w.b / 1024), players: c.n, dataMade: (m.metadata && m.metadata.t) || 0, homeLinked: HOME_KEY !== "" });
}

// ------------------------------------------------------------------ the home server

let homeKey = null;
async function verify(req, body) {
  if (!HOME_KEY) return false;
  const ts = Number(req.headers.get("x-dcf-time") || "0");
  const sig = req.headers.get("x-dcf-sig") || "";
  if (!ts || Math.abs(now() - ts) > SIG_WINDOW || !sig) return false;
  if (!homeKey) homeKey = await crypto.subtle.importKey("raw", unb64(HOME_KEY), { name: "Ed25519" }, false, ["verify"]);
  const url = new URL(req.url);
  const sum = hex(await crypto.subtle.digest("SHA-256", body));
  const msg = new TextEncoder().encode(req.method + "\n" + url.pathname + "\n" + ts + "\n" + sum);
  try {
    return await crypto.subtle.verify({ name: "Ed25519" }, homeKey, unb64(sig), msg);
  } catch (e) {
    return false;
  }
}

async function home(req, env, p) {
  if (!HOME_KEY) return json({ error: "The home server isn't linked yet." }, 503);
  const body = await req.arrayBuffer();
  if (!(await verify(req, body))) return json({ error: "Not signed." }, 403);

  if (p === "/home/pull" && req.method === "POST") {
    const rows = (await env.DB.prepare("select id, ver, pc, ip, app, at, length(body) as size from pending order by at limit ?").bind(PULL_MAX).all()).results;
    const out = [];
    let bytes = 0;
    for (const r of rows) {
      if (out.length > 0 && bytes + r.size > PULL_BYTES) break;
      const b = await env.DB.prepare("select body, ver from pending where id = ?").bind(r.id).first();
      if (!b) continue;
      const c = await env.DB.prepare("select first, uploads from clients where id = ?").bind(r.id).first();
      out.push({ id: r.id, ver: b.ver, pc: r.pc, ip: r.ip, app: r.app, at: r.at, first: c ? c.first : r.at, uploads: c ? c.uploads : 1, body: b.body });
      bytes += r.size;
    }
    const left = await env.DB.prepare("select count(*) as n from pending").first();
    return json({ uploads: out, left: left.n - out.length });
  }

  if (p === "/home/ack" && req.method === "POST") {
    const a = JSON.parse(new TextDecoder().decode(body) || "{}");
    const list = Array.isArray(a.done) ? a.done.slice(0, 200) : [];
    const st = [];
    for (const d of list) {
      if (d && ID_RE.test(d.id) && Number.isInteger(d.ver)) st.push(env.DB.prepare("delete from pending where id = ? and ver = ?").bind(d.id, d.ver));
    }
    if (st.length) await env.DB.batch(st);
    return json({ ok: true, deleted: st.length });
  }

  if (p === "/home/data" && req.method === "PUT") {
    const u = new Uint8Array(body);
    if (u.length < 20 || u[0] !== 0x1f || u[1] !== 0x8b) return json({ error: "Send it gzipped." }, 400);
    const etag = '"' + hex(await crypto.subtle.digest("SHA-256", body)).slice(0, 16) + '"';
    await env.DATA.put("data", body, { metadata: { etag, t: now() } });
    return json({ ok: true, etag });
  }

  if (p === "/home/bans" && req.method === "PUT") {
    const a = JSON.parse(new TextDecoder().decode(body) || "{}");
    const list = Array.isArray(a.bans) ? a.bans : [];
    const st = [env.DB.prepare("delete from bans")];
    for (const b of list) {
      if (!b || !["id", "pc", "ip"].includes(b.kind) || typeof b.value !== "string" || !/^[0-9a-f]{32,64}$/.test(b.value)) continue;
      st.push(env.DB.prepare("insert or replace into bans (kind, value, until) values (?, ?, ?)").bind(b.kind, b.value, Number(b.until) || 0));
    }
    await env.DB.batch(st);
    return json({ ok: true, bans: st.length - 1 });
  }
  return json({ error: "Not found." }, 404);
}
