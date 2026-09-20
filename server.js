const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const port = process.env.PORT || 3000;
const DATA_KEYS = new Set(['products', 'categories', 'ingredients', 'recipes', 'customers', 'transactions', 'expenses', 'beans', 'holdCarts', 'settings']);
const db = new DatabaseSync(path.join(__dirname, 'nexpos.db'));
db.exec(`CREATE TABLE IF NOT EXISTS app_data (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL CHECK(json_valid(value)),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);
db.exec(`CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);
db.exec(`CREATE TABLE IF NOT EXISTS payment_webhooks (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    payload TEXT NOT NULL,
    received_at TEXT NOT NULL
)`);
const getAllData = db.prepare('SELECT key, value, updated_at FROM app_data');
const upsertData = db.prepare(`INSERT INTO app_data (key, value, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`);
const getUserByEmail = db.prepare('SELECT email, password_hash, name FROM users WHERE email = ?');
const countUsers = db.prepare('SELECT COUNT(*) AS count FROM users');
const insertUser = db.prepare('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)');
const updateUserCredentials = db.prepare('UPDATE users SET email = ?, password_hash = ? WHERE email = ?');
const insertWebhook = db.prepare(`INSERT OR IGNORE INTO payment_webhooks (id, provider, payload, received_at)
    VALUES (?, ?, ?, ?)`);
const getWebhooks = db.prepare(`SELECT id, provider, payload, received_at FROM payment_webhooks
    WHERE provider = ? ORDER BY received_at DESC LIMIT 20`);
const sessions = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}

function verifyPassword(password, stored) {
    const [salt, expected] = stored.split(':');
    if (!salt || !expected) return false;
    const actual = crypto.scryptSync(password, salt, 64).toString('hex');
    return actual.length === expected.length && crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

if (countUsers.get().count === 0) {
    const email = process.env.NEXPOS_ADMIN_EMAIL || 'admin@nexpos.local';
    const password = process.env.NEXPOS_ADMIN_PASSWORD || 'NexPOS!2026';
    insertUser.run(email.toLowerCase(), hashPassword(password), 'Admin Studio');
}

const json = (res, status, data) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
};

const getCookie = (req, name) => (req.headers.cookie || '').split(';').map(item => item.trim()).find(item => item.startsWith(`${name}=`))?.slice(name.length + 1);
const currentUser = req => sessions.get(getCookie(req, 'nexpos_session')) || null;
const requireUser = (req, res) => {
    const user = currentUser(req);
    if (!user) json(res, 401, { error: 'Sesi login tidak valid' });
    return user;
};

function readBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => { body += chunk; if (body.length > 5_000_000) reject(new Error('Payload too large')); });
        req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch (error) { reject(error); } });
        req.on('error', reject);
    });
}

function readRawBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', chunk => {
            size += chunk.length;
            if (size > 1_000_000) return reject(new Error('Payload terlalu besar'));
            chunks.push(chunk);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}

function readData(req, res, pathname) {
    if (req.method === 'GET' && pathname === '/api/health') {
        return json(res, 200, { ok: true, database: 'sqlite' });
    }
    if (!requireUser(req, res)) return;
    if (req.method === 'GET' && pathname === '/api/data') {
        const data = {};
        for (const row of getAllData.all()) data[row.key] = JSON.parse(row.value);
        return json(res, 200, { data });
    }
    const match = pathname.match(/^\/api\/data\/([^/]+)$/);
    if (!match || req.method !== 'PUT') return json(res, 404, { error: 'API tidak ditemukan' });
    const key = decodeURIComponent(match[1]);
    if (!DATA_KEYS.has(key)) return json(res, 400, { error: 'Koleksi data tidak valid' });
    return readBody(req).then(body => {
        if (!Object.prototype.hasOwnProperty.call(body, 'value')) return json(res, 400, { error: 'Nilai data wajib diisi' });
        const value = JSON.stringify(body.value);
        upsertData.run(key, value, new Date().toISOString());
        json(res, 200, { ok: true });
    }).catch(error => json(res, 400, { error: error.message || 'Data JSON tidak valid' }));
}

function authApi(req, res, pathname) {
    if (req.method === 'GET' && pathname === '/api/auth/me') {
        const user = currentUser(req);
        return json(res, 200, { user: user ? { email: user.email, name: user.name } : null });
    }
    if (req.method === 'POST' && pathname === '/api/auth/login') {
        return readBody(req).then(body => {
            const email = String(body.email || '').trim().toLowerCase();
            const password = String(body.password || '');
            const user = getUserByEmail.get(email);
            if (!user || !verifyPassword(password, user.password_hash)) return json(res, 401, { error: 'Email atau password salah' });
            const token = crypto.randomBytes(32).toString('hex');
            sessions.set(token, { email: user.email, name: user.name });
            res.setHeader('Set-Cookie', `nexpos_session=${token}; HttpOnly; SameSite=Strict; Path=/`);
            return json(res, 200, { user: { email: user.email, name: user.name } });
        }).catch(() => json(res, 400, { error: 'Data login tidak valid' }));
    }
    if (req.method === 'POST' && pathname === '/api/auth/logout') {
        const token = getCookie(req, 'nexpos_session');
        if (token) sessions.delete(token);
        res.setHeader('Set-Cookie', 'nexpos_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
        return json(res, 200, { ok: true });
    }
    if (req.method === 'PATCH' && pathname === '/api/auth/account') {
        const session = currentUser(req);
        if (!session) return json(res, 401, { error: 'Sesi login tidak valid' });
        return readBody(req).then(body => {
            const email = String(body.email || '').trim().toLowerCase();
            const currentPassword = String(body.currentPassword || '');
            const newPassword = String(body.newPassword || '');
            if (!/^\S+@\S+\.\S+$/.test(email)) return json(res, 400, { error: 'Email tidak valid' });
            if (newPassword.length < 8) return json(res, 400, { error: 'Password baru minimal 8 karakter' });
            const user = getUserByEmail.get(session.email);
            if (!user || !verifyPassword(currentPassword, user.password_hash)) return json(res, 401, { error: 'Password lama salah' });
            const existing = getUserByEmail.get(email);
            if (existing && email !== session.email) return json(res, 409, { error: 'Email sudah digunakan' });
            updateUserCredentials.run(email, hashPassword(newPassword), session.email);
            sessions.set(getCookie(req, 'nexpos_session'), { email, name: user.name });
            return json(res, 200, { user: { email, name: user.name } });
        }).catch(() => json(res, 400, { error: 'Data akun tidak valid' }));
    }
    return json(res, 404, { error: 'API autentikasi tidak ditemukan' });
}

function kipayApi(req, res, pathname) {
    if (!requireUser(req, res)) return;
    if (req.method !== 'GET' || pathname !== '/api/kipay/webhooks') return json(res, 404, { error: 'API Kipay tidak ditemukan' });
    const events = getWebhooks.all('kipay').map(event => ({
        id: event.id, receivedAt: event.received_at, payload: JSON.parse(event.payload)
    }));
    return json(res, 200, { events });
}

function kipayWebhook(req, res) {
    if (req.method !== 'POST') return json(res, 405, { error: 'Gunakan POST' });
    return readRawBody(req).then(raw => {
        let payload;
        try { payload = JSON.parse(raw.toString('utf8')); }
        catch { return json(res, 400, { error: 'Payload JSON tidak valid' }); }
        const id = crypto.createHash('sha256').update(raw).digest('hex');
        insertWebhook.run(id, 'kipay', JSON.stringify(payload), new Date().toISOString());
        // Kipay's final transaction fields/signature must be verified before changing any POS order.
        console.log(`Webhook Kipay diterima: ${id}`);
        return json(res, 200, { ok: true });
    }).catch(error => json(res, 400, { error: error.message || 'Webhook gagal diproses' }));
}

function serveStatic(req, res, pathname) {
    const requested = pathname === '/' ? 'index.html' : pathname.slice(1);
    const file = path.resolve(__dirname, requested);
    if (!file.startsWith(path.resolve(__dirname) + path.sep)) return json(res, 403, { error: 'Forbidden' });
    fs.readFile(file, (error, data) => {
        if (error) return json(res, 404, { error: 'Not found' });
        const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png' };
        res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' });
        res.end(data);
    });
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    try {
        if (url.pathname === '/api/webhooks/kipay') return kipayWebhook(req, res);
        if (url.pathname.startsWith('/api/auth/')) return authApi(req, res, url.pathname);
        if (url.pathname.startsWith('/api/kipay/')) return kipayApi(req, res, url.pathname);
        if (url.pathname.startsWith('/api/')) return readData(req, res, url.pathname);
        serveStatic(req, res, url.pathname);
    } catch (error) {
        console.error(error);
        json(res, 500, { error: 'Kesalahan server' });
    }
});

server.listen(port, () => console.log(`NexPOS berjalan di http://localhost:${port}`));
