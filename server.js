const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3333;
const DATA = process.env.VERCEL ? '/tmp' : path.join(__dirname, 'data');
if (!fs.existsSync(DATA)) {
    try { fs.mkdirSync(DATA, { recursive: true }); } catch (e) {}
}

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ═══════ CRYPTO HELPERS ═══════
function salt() { return crypto.randomBytes(16).toString('hex'); }
function hash(pw, s) { return crypto.pbkdf2Sync(pw, s, 10000, 64, 'sha512').toString('hex'); }
function token() { return crypto.randomBytes(32).toString('hex'); }

// ═══════ USER FILE HELPERS ═══════
function safeN(n) { return n.toLowerCase().replace(/[^a-z0-9а-яіїєґ_-]/gi, '_').substring(0, 40); }
function userFile(n) { return path.join(DATA, safeN(n) + '.json'); }

function readUser(name) {
    const f = userFile(name);
    if (!fs.existsSync(f)) return null;
    try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { return null; }
}

function writeUser(name, data) {
    fs.writeFileSync(userFile(name), JSON.stringify(data, null, 2), 'utf8');
}

// Auth middleware
function auth(req, res, next) {
    const t = req.headers['x-token'];
    if (!t) return res.status(401).json({ ok: false, error: 'No token' });
    const user = readUser(req.params.user);
    if (!user) return res.status(401).json({ ok: false, error: 'User not found' });
    if (!user.tokens || !user.tokens.includes(t)) return res.status(401).json({ ok: false, error: 'Invalid token' });
    req.userData = user;
    next();
}

// ═══════ AUTH ROUTES ═══════

// POST /api/register { username, password }
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ ok: false, error: 'Потрібне ім\'я та пароль' });
    if (username.length < 2) return res.status(400).json({ ok: false, error: 'Ім\'я мін. 2 символи' });
    if (password.length < 4) return res.status(400).json({ ok: false, error: 'Пароль мін. 4 символи' });

    const existing = readUser(username);
    if (existing) return res.status(409).json({ ok: false, error: 'Це ім\'я вже зайняте' });

    const s = salt();
    const tk = token();
    const user = {
        username,
        salt: s,
        hash: hash(password, s),
        tokens: [tk],
        state: null,
        history: [],
        completedToday: {} // { "2026-07-14": ["mon","wed"] }
    };
    writeUser(username, user);
    res.json({ ok: true, token: tk, username });
});

// POST /api/login { username, password }
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ ok: false, error: 'Потрібне ім\'я та пароль' });

    const user = readUser(username);
    if (!user) return res.status(401).json({ ok: false, error: 'Невірне ім\'я або пароль' });
    if (hash(password, user.salt) !== user.hash) return res.status(401).json({ ok: false, error: 'Невірне ім\'я або пароль' });

    const tk = token();
    if (!user.tokens) user.tokens = [];
    // Keep max 5 tokens (devices)
    user.tokens.push(tk);
    if (user.tokens.length > 5) user.tokens = user.tokens.slice(-5);
    writeUser(username, user);
    res.json({ ok: true, token: tk, username });
});

// GET /api/me/:user — validate session
app.get('/api/me/:user', auth, (req, res) => {
    res.json({ ok: true, username: req.userData.username });
});

// ═══════ STATE ROUTES ═══════

// GET /api/state/:user
app.get('/api/state/:user', auth, (req, res) => {
    res.json({ ok: true, data: req.userData.state || null, completed: req.userData.completedToday || {} });
});

// POST /api/state/:user
app.post('/api/state/:user', auth, (req, res) => {
    const user = req.userData;
    user.state = req.body.state || null;
    // Merge completed days
    if (req.body.completed) {
        if (!user.completedToday) user.completedToday = {};
        Object.assign(user.completedToday, req.body.completed);
        // Clean up old dates (keep last 90 days)
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - 90);
        const cutStr = cutoff.toISOString().split('T')[0];
        for (const d in user.completedToday) {
            if (d < cutStr) delete user.completedToday[d];
        }
    }
    user.state._saved = new Date().toISOString();
    writeUser(req.params.user, user);
    res.json({ ok: true });
});

// POST /api/complete/:user — mark a day as completed
app.post('/api/complete/:user', auth, (req, res) => {
    const { date, dayKey } = req.body;
    const user = req.userData;
    if (!user.completedToday) user.completedToday = {};
    if (!user.completedToday[date]) user.completedToday[date] = [];
    if (!user.completedToday[date].includes(dayKey)) {
        user.completedToday[date].push(dayKey);
    }
    // Add to history
    if (!user.history) user.history = [];
    user.history.push({ ...req.body, _ts: new Date().toISOString() });
    if (user.history.length > 500) user.history = user.history.slice(-500);
    writeUser(req.params.user, user);
    res.json({ ok: true });
});

// GET /api/history/:user
app.get('/api/history/:user', auth, (req, res) => {
    res.json({ ok: true, data: req.userData.history || [] });
});

// Fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  AESTHETIX SERVER — http://localhost:${PORT}`);
    console.log(`  Data: ${DATA}\n`);
});
