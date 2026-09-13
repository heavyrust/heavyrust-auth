const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 8080;
const VALID_TOKEN = '7e8b839f2048991a';
const USERS_FILE = path.join(__dirname, 'users.json');

app.use(cors());
app.use(express.json());

// -------------------------------------------------------------
// USER DATABASE & AUTH SYSTEM
// -------------------------------------------------------------
let users = {};

function hashPassword(pwd) {
    return crypto.createHash('sha256').update(String(pwd) + '_heavyrust_salt_2026').digest('hex');
}

function loadUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        }
    } catch (e) {
        console.error('Error loading users.json:', e);
        users = {};
    }

    // Set/Ensure Master Owner Account (c0d3r / ma1235150)
    users['c0d3r'] = {
        username: 'c0d3r',
        passwordHash: hashPassword('ma1235150'),
        role: 'owner',
        active: true,
        hwid: '',
        createdAt: (users['c0d3r'] && users['c0d3r'].createdAt) || new Date().toISOString(),
        lastLogin: (users['c0d3r'] && users['c0d3r'].lastLogin) || null
    };

    // Remove legacy placeholder owner if exists
    if (users['owner']) {
        delete users['owner'];
    }

    saveUsers();
}

function saveUsers() {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
    } catch (e) {
        console.error('Error saving users.json:', e);
    }
}

loadUsers();

// In-memory active tokens & sessions
const userTokens = new Map();   // token -> { username, role, hwid, createdAt }
const adminTokens = new Set();  // set of admin/owner tokens
const sessions = new Map();     // steamId -> player session
const screenRequests = new Map(); // target -> timestamp

// Middleware to verify admin token
function requireAdmin(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();

    if (!token || !adminTokens.has(token)) {
        return res.status(401).json({ status: 'error', message: 'Unauthorized: Owner or Admin rights required' });
    }
    next();
}

// Cleanup expired sessions
setInterval(() => {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [id, session] of sessions.entries()) {
        if (session.lastHeartbeat < cutoff) {
            sessions.delete(id);
        }
    }
}, 60000);

// Self-keepalive ping to prevent Render free tier sleep
setInterval(() => {
    https.get('https://heavyrust-auth.onrender.com/api/players', (res) => {
        res.on('data', () => {});
    }).on('error', () => {});
}, 9 * 60 * 1000);

// -------------------------------------------------------------
// AUTHENTICATION APIS (FOR LAUNCHER & ADMIN PANEL)
// -------------------------------------------------------------

// 1. User Login (Launcher or Web Panel)
app.post('/api/auth/login', (req, res) => {
    const { username, password, hwid } = req.body || {};
    const cleanUser = String(username || '').trim().toLowerCase();

    const user = users[cleanUser];
    if (!user) {
        return res.status(401).json({ success: false, message: 'Пользователь с таким логином не найден' });
    }

    if (!user.active) {
        return res.status(403).json({ success: false, message: 'Ваш аккаунт заблокирован администратором!' });
    }

    const hashed = hashPassword(password);
    if (user.passwordHash !== hashed) {
        return res.status(401).json({ success: false, message: 'Неверный пароль' });
    }

    // HWID binding for regular users
    if (hwid && user.role !== 'owner' && user.role !== 'admin') {
        if (user.hwid && user.hwid !== hwid) {
            return res.status(403).json({ success: false, message: 'Вход разрешен только с привязанного ПК (HWID не совпадает)!' });
        }
        if (!user.hwid) {
            user.hwid = hwid;
        }
    }

    user.lastLogin = new Date().toISOString();
    saveUsers();

    // Generate secure session token
    const token = crypto.randomBytes(32).toString('hex');
    userTokens.set(token, {
        username: user.username,
        role: user.role,
        hwid: hwid || user.hwid || '',
        createdAt: Date.now()
    });

    if (user.role === 'owner' || user.role === 'admin') {
        adminTokens.add(token);
    }

    res.json({
        success: true,
        token: token,
        username: user.username,
        role: user.role,
        message: 'Авторизация успешна'
    });
});

// 2. Verify Token (Launcher startup check)
app.post('/api/auth/verify_token', (req, res) => {
    const { token } = req.body || {};
    if (!token || !userTokens.has(token)) {
        return res.json({ valid: false, message: 'Сессия недействительна' });
    }

    const session = userTokens.get(token);
    const user = users[session.username.toLowerCase()];

    if (!user || !user.active) {
        userTokens.delete(token);
        adminTokens.delete(token);
        return res.json({ valid: false, message: 'Пользователь заблокирован или удален' });
    }

    res.json({
        valid: true,
        username: user.username,
        role: user.role
    });
});

// -------------------------------------------------------------
// OWNER & ADMIN USER MANAGEMENT APIS
// -------------------------------------------------------------

// List all users
app.get('/api/admin/users', requireAdmin, (req, res) => {
    const list = Object.values(users).map(u => ({
        username: u.username,
        role: u.role,
        active: Boolean(u.active),
        hwid: u.hwid || '',
        createdAt: u.createdAt,
        lastLogin: u.lastLogin
    }));
    res.json(list);
});

// Update Owner profile (change login & password)
app.post('/api/admin/profile/update', requireAdmin, (req, res) => {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    const session = userTokens.get(token);

    if (!session || session.role !== 'owner') {
        return res.status(403).json({ success: false, message: 'Только Главный Овнер может менять эти данные!' });
    }

    const currentKey = session.username.toLowerCase();
    const { newUsername, newPassword } = req.body || {};

    const cleanNewUser = String(newUsername || session.username).trim();
    const cleanNewKey = cleanNewUser.toLowerCase();

    if (cleanNewUser.length < 3) {
        return res.status(400).json({ success: false, message: 'Логин должен содержать от 3 символов' });
    }

    const ownerData = users[currentKey] || {
        role: 'owner',
        active: true,
        createdAt: new Date().toISOString()
    };

    if (newPassword && String(newPassword).length >= 4) {
        ownerData.passwordHash = hashPassword(newPassword);
    }

    if (cleanNewKey !== currentKey) {
        if (users[cleanNewKey]) {
            return res.status(400).json({ success: false, message: 'Пользователь с таким логином уже существует!' });
        }
        delete users[currentKey];
    }

    ownerData.username = cleanNewUser;
    users[cleanNewKey] = ownerData;
    saveUsers();

    session.username = cleanNewUser;

    res.json({
        success: true,
        username: cleanNewUser,
        message: 'Данные профиля успешно обновлены!'
    });
});

// Create new user
app.post('/api/admin/users/create', requireAdmin, (req, res) => {
    const { username, password, role } = req.body || {};
    const cleanUser = String(username || '').trim().toLowerCase();

    if (!cleanUser || cleanUser.length < 3) {
        return res.status(400).json({ success: false, message: 'Логин должен содержать минимум 3 символа' });
    }
    if (!password || String(password).length < 4) {
        return res.status(400).json({ success: false, message: 'Пароль должен содержать минимум 4 символа' });
    }
    if (users[cleanUser]) {
        return res.status(400).json({ success: false, message: 'Пользователь с таким логином уже существует!' });
    }

    users[cleanUser] = {
        username: String(username).trim(),
        passwordHash: hashPassword(password),
        role: role === 'admin' ? 'admin' : 'user',
        active: true,
        hwid: '',
        createdAt: new Date().toISOString(),
        lastLogin: null
    };
    saveUsers();

    res.json({ success: true, message: `Пользователь ${username} успешно создан!` });
});

// Toggle user active status (Block / Unblock)
app.post('/api/admin/users/toggle', requireAdmin, (req, res) => {
    const { username } = req.body || {};
    const cleanUser = String(username || '').trim().toLowerCase();

    if (cleanUser === 'c0d3r' || (users[cleanUser] && users[cleanUser].role === 'owner')) {
        return res.status(400).json({ success: false, message: 'Нельзя заблокировать главный аккаунт!' });
    }

    const user = users[cleanUser];
    if (!user) {
        return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    user.active = !user.active;
    saveUsers();

    // Revoke active sessions if blocked
    if (!user.active) {
        for (const [tok, sess] of userTokens.entries()) {
            if (sess.username.toLowerCase() === cleanUser) {
                userTokens.delete(tok);
                adminTokens.delete(tok);
            }
        }
    }

    res.json({ success: true, active: user.active, message: user.active ? 'Пользователь разблокирован' : 'Пользователь заблокирован' });
});

// Reset user HWID
app.post('/api/admin/users/reset_hwid', requireAdmin, (req, res) => {
    const { username } = req.body || {};
    const cleanUser = String(username || '').trim().toLowerCase();

    const user = users[cleanUser];
    if (!user) {
        return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    user.hwid = '';
    saveUsers();
    res.json({ success: true, message: `HWID пользователя ${user.username} успешно сброшен.` });
});

// Reset user password
app.post('/api/admin/users/reset_password', requireAdmin, (req, res) => {
    const { username, newPassword } = req.body || {};
    const cleanUser = String(username || '').trim().toLowerCase();

    const user = users[cleanUser];
    if (!user) {
        return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    if (!newPassword || String(newPassword).length < 4) {
        return res.status(400).json({ success: false, message: 'Пароль должен содержать от 4 символов' });
    }

    user.passwordHash = hashPassword(newPassword);
    saveUsers();

    res.json({ success: true, message: `Пароль для ${user.username} успешно изменён!` });
});

// Delete user
app.post('/api/admin/users/delete', requireAdmin, (req, res) => {
    const { username } = req.body || {};
    const cleanUser = String(username || '').trim().toLowerCase();

    if (cleanUser === 'c0d3r' || (users[cleanUser] && users[cleanUser].role === 'owner')) {
        return res.status(400).json({ success: false, message: 'Нельзя удалить главный аккаунт!' });
    }

    if (!users[cleanUser]) {
        return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    delete users[cleanUser];
    saveUsers();

    res.json({ success: true, message: `Пользователь ${username} успешно удалён.` });
});

// -------------------------------------------------------------
// LAUNCHER & SERVER PULSE / VERIFICATION APIS
// -------------------------------------------------------------

// Heartbeat from HeavyRustLauncher
app.post('/api/heartbeat', (req, res) => {
    const { steamId, nickname, hwid, token, gamePid } = req.body || {};

    if (token !== VALID_TOKEN) {
        return res.status(403).json({ status: 'error', message: 'Invalid token' });
    }

    const sid = String(steamId || '').trim();
    if (!sid || sid === '0') {
        return res.status(400).json({ status: 'error', message: 'Missing valid steamId' });
    }

    let screenRequested = false;
    if (screenRequests.has(sid) || (hwid && screenRequests.has(hwid))) {
        screenRequested = true;
        screenRequests.delete(sid);
        if (hwid) screenRequests.delete(hwid);
    }

    const displayNick = (nickname && nickname !== 'Player #heavyrust' && nickname !== 'Player')
        ? String(nickname).trim()
        : 'Игрок';

    sessions.set(sid, {
        steamId: sid,
        nickname: displayNick,
        hwid: hwid || '',
        ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
        gamePid: gamePid || 0,
        lastHeartbeat: Date.now()
    });

    res.json({ status: 'ok', valid: true, request_screen: screenRequested });
});

// Check player by steamid or nickname
app.get('/api/check', (req, res) => {
    const steamId = String(req.query.steamid || '').trim();
    const nickname = String(req.query.nickname || req.query.name || '').trim();
    const session = findActiveSession(steamId, nickname);

    if (session && (Date.now() - session.lastHeartbeat) <= 35000) {
        const secondsAgo = Math.round((Date.now() - session.lastHeartbeat) / 1000);
        res.json({ steamId: session.steamId, valid: true, nickname: session.nickname, hwid: session.hwid, secondsAgo });
    } else {
        res.json({ steamId, valid: false, message: 'No active launcher session found' });
    }
});

// Bearer token for HeavyAC
app.post('/internal_get_bearer_token', (req, res) => {
    res.json({ token: VALID_TOKEN });
});

// Find active session helper
function findActiveSession(userId, playerName) {
    if (userId) {
        const byId = sessions.get(String(userId));
        if (byId && (Date.now() - byId.lastHeartbeat) <= 35000) return byId;
    }
    if (playerName) {
        const cleanName = String(playerName).trim().toLowerCase();
        for (const s of sessions.values()) {
            if (s.nickname && s.nickname.trim().toLowerCase() === cleanName) {
                if ((Date.now() - s.lastHeartbeat) <= 35000) return s;
            }
        }
    }
    return null;
}

// Single player check on join for HeavyAC.cs
app.post('/internal_player_state', (req, res) => {
    const list = Array.isArray(req.body) ? req.body : [req.body];
    const first = list[0] || {};
    const id = String(first.userId || first.userid || '');
    const name = String(first.playerName || first.name || '');
    const session = findActiveSession(id, name);
    const isValid = Boolean(session);
    res.json({
        userId: id,
        valid: isValid,
        hban: false,
        hbanMessage: '',
        hwid: (session && session.hwid) || ''
    });
});

// Bulk check for HeavyAC.cs
app.post('/internal_players_check', (req, res) => {
    const playerList = Array.isArray(req.body) ? req.body : [];
    const results = playerList.map(p => {
        const id = String(p.userId || p.userid || '');
        const name = String(p.playerName || p.name || '');
        const session = findActiveSession(id, name);
        const isValid = Boolean(session);
        return {
            userId: id,
            valid: isValid,
            hban: false,
            hbanMessage: '',
            hwid: (session && session.hwid) || ''
        };
    });
    res.json(results);
});

// Screen request API
app.post('/api/screen_request', (req, res) => {
    const { target } = req.body || {};
    if (target) {
        screenRequests.set(String(target), Date.now());
        return res.json({ status: 'ok', message: 'Screenshot request queued' });
    }
    res.status(400).json({ status: 'error', message: 'Missing target' });
});

// Active players list
app.get('/api/players', (req, res) => {
    const now = Date.now();
    const list = Array.from(sessions.values()).map(s => ({
        steamId: s.steamId,
        nickname: s.nickname,
        hwid: s.hwid,
        ip: s.ip,
        active: (now - s.lastHeartbeat) <= 35000,
        secondsAgo: Math.round((now - s.lastHeartbeat) / 1000)
    }));
    res.json(list);
});

// -------------------------------------------------------------
// WEB ADMIN PANEL (OWNER DASHBOARD)
// -------------------------------------------------------------
app.get(['/', '/index.html', '/admin'], (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Heavy Rust • Панель управления и Античит</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0D1117; --bg-card: #161B22; --bg-header: #21262D; --bg-input: #0A0D12;
            --border-color: rgba(255, 255, 255, 0.1); --cyan-neon: #00E5FF;
            --green-active: #00E676; --red-alert: #FF3366; --gold: #FFB300; --text-main: #F0F6FC; --text-muted: #8B949E;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Outfit', sans-serif; background: var(--bg-base); color: var(--text-main); min-height: 100vh; display: flex; justify-content: center; padding: 24px 16px; }
        .container { width: 100%; max-width: 1200px; display: flex; flex-direction: column; gap: 20px; }
        
        /* HEADER */
        .header { display: flex; align-items: center; justify-content: space-between; padding: 20px 28px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; }
        .logo-box h1 { font-size: 22px; font-weight: 800; color: var(--cyan-neon); text-transform: uppercase; letter-spacing: 0.5px; }
        .user-badge { display: flex; align-items: center; gap: 12px; }
        .role-tag { background: rgba(255, 179, 0, 0.15); color: var(--gold); border: 1px solid rgba(255, 179, 0, 0.4); padding: 4px 12px; border-radius: 20px; font-size: 13px; font-weight: 700; }
        
        /* TABS & SEARCH */
        .tabs-row { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
        .tabs { display: flex; gap: 10px; }
        .tab-btn { background: none; border: none; color: var(--text-muted); font-size: 15px; font-weight: 600; padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: all 0.2s; }
        .tab-btn.active { color: var(--cyan-neon); background: rgba(0, 229, 255, 0.1); border: 1px solid rgba(0, 229, 255, 0.3); }
        .tab-btn:hover:not(.active) { color: var(--text-main); background: rgba(255, 255, 255, 0.05); }

        .search-wrap { position: relative; min-width: 320px; }
        .search-input { width: 100%; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px; padding: 10px 14px 10px 38px; color: #fff; font-size: 14px; outline: none; transition: 0.2s; }
        .search-input:focus { border-color: var(--cyan-neon); box-shadow: 0 0 10px rgba(0, 229, 255, 0.25); }
        .search-icon { position: absolute; left: 12px; top: 10px; font-size: 14px; opacity: 0.6; }

        /* CARDS & TABLES */
        .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 22px; display: flex; flex-direction: column; gap: 16px; }
        .card-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; }
        .card-title { font-size: 18px; font-weight: 700; color: var(--text-main); }
        .btn-action { background: var(--cyan-neon); color: #000; border: none; padding: 9px 18px; border-radius: 8px; font-weight: 700; font-size: 14px; cursor: pointer; transition: 0.2s; }
        .btn-action:hover { background: #33EBFF; box-shadow: 0 0 15px rgba(0, 229, 255, 0.4); }
        .btn-danger { background: rgba(255, 51, 102, 0.15); color: var(--red-alert); border: 1px solid rgba(255, 51, 102, 0.3); padding: 6px 12px; border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer; }
        .btn-danger:hover { background: var(--red-alert); color: #fff; }
        .btn-secondary { background: rgba(255, 255, 255, 0.08); color: var(--text-main); border: 1px solid var(--border-color); padding: 6px 12px; border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer; }
        .btn-secondary:hover { background: rgba(255, 255, 255, 0.15); }
        .btn-logout { background: rgba(255, 255, 255, 0.06); color: var(--text-muted); border: 1px solid var(--border-color); padding: 6px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600; }
        .btn-logout:hover { color: var(--red-alert); border-color: var(--red-alert); }

        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: var(--bg-header); padding: 12px 16px; font-size: 13px; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border-color); }
        td { padding: 14px 16px; font-size: 14px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
        tr:hover { background: rgba(0, 229, 255, 0.02); }
        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .badge-active { background: rgba(0, 230, 118, 0.15); color: var(--green-active); }
        .badge-blocked { background: rgba(255, 51, 102, 0.15); color: var(--red-alert); }
        .pulse-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; box-shadow: 0 0 8px currentColor; }
        .mono { font-family: 'JetBrains Mono', monospace; font-size: 13px; }

        /* MODAL */
        .modal-overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 100; }
        .modal-card { background: var(--bg-card); border: 1px solid rgba(0, 229, 255, 0.3); width: 100%; max-width: 440px; border-radius: 16px; padding: 28px; display: flex; flex-direction: column; gap: 18px; box-shadow: 0 0 40px rgba(0, 229, 255, 0.15); }
        .modal-card h2 { font-size: 20px; font-weight: 700; color: var(--cyan-neon); }
        .form-group { display: flex; flex-direction: column; gap: 8px; }
        .form-group label { font-size: 13px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }
        .form-control { background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px 14px; color: #fff; font-size: 15px; outline: none; transition: 0.2s; }
        .form-control:focus { border-color: var(--cyan-neon); box-shadow: 0 0 10px rgba(0, 229, 255, 0.2); }
        .modal-btns { display: flex; gap: 10px; justify-content: flex-end; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container" id="appContainer">
        <!-- Auth Login Screen (if not logged in) -->
        <div id="loginScreen" class="modal-overlay" style="display: none;">
            <div class="modal-card">
                <h2>Вход в панель</h2>
                <p style="color: var(--text-muted); font-size: 14px;">Введите данные для доступа к панели управления:</p>
                <div class="form-group">
                    <label>Логин</label>
                    <input type="text" id="adminLoginUser" class="form-control" placeholder="Логин">
                </div>
                <div class="form-group">
                    <label>Пароль</label>
                    <input type="password" id="adminLoginPass" class="form-control" placeholder="••••••••" onkeydown="if(event.key==='Enter')loginAdmin()">
                </div>
                <div id="loginError" style="color: var(--red-alert); font-size: 13px; display: none;"></div>
                <button class="btn-action" onclick="loginAdmin()" style="margin-top: 6px; padding: 12px;">Войти в панель управления</button>
            </div>
        </div>

        <!-- Main Dashboard Header -->
        <div class="header">
            <div class="logo-box">
                <h1>🛡️ Heavy Rust • Master Admin Panel</h1>
                <p style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Центральный сервер аутентификации, базы игроков и античита</p>
            </div>
            <div class="user-badge">
                <span class="role-tag">🛡️ Администратор: <span id="currentAdminName">Admin</span></span>
                <button class="btn-secondary" onclick="openProfileModal()">⚙️ Мой аккаунт</button>
                <button class="btn-logout" onclick="logoutAdmin()">Выйти</button>
            </div>
        </div>

        <!-- Navigation Tabs & Real-Time Search Bar -->
        <div class="tabs-row">
            <div class="tabs">
                <button class="tab-btn active" onclick="switchTab('onlineTab', this)">🎮 Онлайн в лаунчере</button>
                <button class="tab-btn" onclick="switchTab('usersTab', this)">👥 Пользователи (Аккаунты)</button>
            </div>
            <div class="search-wrap">
                <span class="search-icon">🔍</span>
                <input type="text" id="searchFilter" class="search-input" placeholder="Поиск по никнейму, SteamID или HWID..." oninput="handleSearch()">
            </div>
        </div>

        <!-- TAB 1: ONLINE PLAYERS -->
        <div id="onlineTab" class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">Игроки с активным лаунчером в реальном времени</div>
                    <div style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Никнеймы, реальные SteamID64, цифровой HWID и статус сессии</div>
                </div>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Статус</th>
                            <th>Никнейм / Логин</th>
                            <th>SteamID64</th>
                            <th>HWID ПК</th>
                            <th>Пульс</th>
                            <th>Действие</th>
                        </tr>
                    </thead>
                    <tbody id="onlineTbody">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">Загрузка...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 2: USERS -->
        <div id="usersTab" class="card" style="display: none;">
            <div class="card-header">
                <div>
                    <div class="card-title">Управление учетными записями игроков</div>
                    <div style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Только созданные здесь пользователи могут войти в лаунчер и на сервер</div>
                </div>
                <button class="btn-action" onclick="openCreateUserModal()">+ Создать пользователя</button>
            </div>

            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Логин</th>
                            <th>Роль</th>
                            <th>Статус</th>
                            <th>Привязанный HWID</th>
                            <th>Последний вход</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody id="usersTbody">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">Загрузка пользователей...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- PROFILE SETTINGS MODAL -->
    <div id="profileModal" class="modal-overlay" style="display: none;">
        <div class="modal-card">
            <h2>⚙️ Настройки аккаунта</h2>
            <p style="color: var(--text-muted); font-size: 13px;">Измените логин или пароль для входа в панель:</p>
            <div class="form-group">
                <label>Ваш логин</label>
                <input type="text" id="profileUser" class="form-control" placeholder="Логин">
            </div>
            <div class="form-group">
                <label>Новый пароль (оставьте пустым если не хотите менять)</label>
                <input type="text" id="profilePass" class="form-control" placeholder="Новый надежный пароль">
            </div>
            <div id="profileError" style="color: var(--red-alert); font-size: 13px; display: none;"></div>
            <div id="profileSuccess" style="color: var(--green-active); font-size: 13px; display: none;"></div>
            <div class="modal-btns">
                <button class="btn-secondary" onclick="closeProfileModal()">Закрыть</button>
                <button class="btn-action" onclick="submitProfileUpdate()">Сохранить</button>
            </div>
        </div>
    </div>

    <!-- CREATE USER MODAL -->
    <div id="createUserModal" class="modal-overlay" style="display: none;">
        <div class="modal-card">
            <h2>➕ Создать пользователя лаунчера</h2>
            <div class="form-group">
                <label>Логин (никнейм для входа)</label>
                <input type="text" id="newUsername" class="form-control" placeholder="Например: alex_rust">
            </div>
            <div class="form-group">
                <label>Пароль</label>
                <input type="text" id="newPassword" class="form-control" placeholder="Например: rust12345">
            </div>
            <div class="form-group">
                <label>Роль</label>
                <select id="newRole" class="form-control">
                    <option value="user">Игрок (User)</option>
                    <option value="admin">Администратор (Admin)</option>
                </select>
            </div>
            <div id="createError" style="color: var(--red-alert); font-size: 13px; display: none;"></div>
            <div class="modal-btns">
                <button class="btn-secondary" onclick="closeCreateUserModal()">Отмена</button>
                <button class="btn-action" onclick="submitCreateUser()">Создать аккаунт</button>
            </div>
        </div>
    </div>

    <!-- RESET PASSWORD MODAL -->
    <div id="resetPassModal" class="modal-overlay" style="display: none;">
        <div class="modal-card">
            <h2>🔑 Смена пароля пользователя</h2>
            <p style="color: var(--text-muted); font-size: 14px;">Пользователь: <strong id="resetTargetUser" style="color: #fff;"></strong></p>
            <div class="form-group">
                <label>Новый пароль</label>
                <input type="text" id="resetNewPass" class="form-control" placeholder="Новый пароль">
            </div>
            <div id="resetError" style="color: var(--red-alert); font-size: 13px; display: none;"></div>
            <div class="modal-btns">
                <button class="btn-secondary" onclick="closeResetPassModal()">Отмена</button>
                <button class="btn-action" onclick="submitResetPassword()">Сохранить пароль</button>
            </div>
        </div>
    </div>

    <script>
        let adminToken = localStorage.getItem('heavy_admin_token') || '';
        let cachedUsers = [];
        let cachedPlayers = [];

        function checkAuth() {
            if (!adminToken) {
                document.getElementById('loginScreen').style.display = 'flex';
            } else {
                document.getElementById('loginScreen').style.display = 'none';
                loadUsers();
                loadOnline();
            }
        }

        async function loginAdmin() {
            const u = document.getElementById('adminLoginUser').value.trim();
            const p = document.getElementById('adminLoginPass').value.trim();
            const err = document.getElementById('loginError');
            err.style.display = 'none';

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: u, password: p })
                });
                const data = await res.json();
                if (data.success && (data.role === 'owner' || data.role === 'admin')) {
                    adminToken = data.token;
                    localStorage.setItem('heavy_admin_token', adminToken);
                    document.getElementById('currentAdminName').innerText = data.username;
                    document.getElementById('loginScreen').style.display = 'none';
                    loadUsers();
                    loadOnline();
                } else {
                    err.innerText = data.message || 'Требуются права Администратора!';
                    err.style.display = 'block';
                }
            } catch (e) {
                err.innerText = 'Ошибка соединения: ' + e;
                err.style.display = 'block';
            }
        }

        function logoutAdmin() {
            localStorage.removeItem('heavy_admin_token');
            adminToken = '';
            location.reload();
        }

        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('onlineTab').style.display = tabId === 'onlineTab' ? 'flex' : 'none';
            document.getElementById('usersTab').style.display = tabId === 'usersTab' ? 'flex' : 'none';
            handleSearch();
        }

        function handleSearch() {
            const query = (document.getElementById('searchFilter').value || '').trim().toLowerCase();
            renderOnline(query);
            renderUsers(query);
        }

        async function loadUsers() {
            if (!adminToken) return;
            try {
                const res = await fetch('/api/admin/users', { headers: { 'Authorization': 'Bearer ' + adminToken } });
                if (res.status === 401) { logoutAdmin(); return; }
                cachedUsers = await res.json();
                renderUsers((document.getElementById('searchFilter').value || '').trim().toLowerCase());
            } catch (e) { console.error(e); }
        }

        function renderUsers(query) {
            const tbody = document.getElementById('usersTbody');
            const filtered = cachedUsers.filter(u => {
                if (!query) return true;
                return (u.username || '').toLowerCase().includes(query) ||
                       (u.hwid || '').toLowerCase().includes(query);
            });

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">Пользователи не найдены.</td></tr>';
                return;
            }

            tbody.innerHTML = filtered.map(u => \`
                <tr>
                    <td style="font-weight: 700; color: #fff;">\${escapeHtml(u.username)}</td>
                    <td><span class="role-tag" style="\${u.role === 'owner' ? '' : 'background: rgba(0,229,255,0.1); color: var(--cyan-neon); border-color: rgba(0,229,255,0.3);'}">\${u.role === 'owner' ? 'ADMIN' : u.role.toUpperCase()}</span></td>
                    <td><span class="badge \${u.active ? 'badge-active' : 'badge-blocked'}"><span class="pulse-dot"></span> \${u.active ? 'АКТИВЕН' : 'ЗАБЛОКИРОВАН'}</span></td>
                    <td>
                        <span class="mono" style="font-size: 11px; color: var(--text-muted);">\${u.hwid ? u.hwid : 'Не привязан'}</span>
                        \${u.hwid ? \`<button class="btn-secondary" style="margin-left: 6px; padding: 2px 6px; font-size: 11px;" onclick="resetHwid('\${escapeHtml(u.username)}')">Сброс HWID</button>\` : ''}
                    </td>
                    <td style="font-size: 12px; color: var(--text-muted);">\${u.lastLogin ? new Date(u.lastLogin).toLocaleString('ru-RU') : 'Ещё не входил'}</td>
                    <td>
                        <div style="display: flex; gap: 6px;">
                            \${u.role !== 'owner' ? \`
                                <button class="btn-secondary" onclick="toggleUser('\${escapeHtml(u.username)}')">\${u.active ? 'Заблокировать' : 'Разблокировать'}</button>
                                <button class="btn-secondary" onclick="openResetPassModal('\${escapeHtml(u.username)}')">Пароль</button>
                                <button class="btn-danger" onclick="deleteUser('\${escapeHtml(u.username)}')">Удалить</button>
                            \` : '<span style="color: var(--gold); font-size: 12px; font-weight: 600;">Главный Администратор</span>'}
                        </div>
                    </td>
                </tr>
            \`).join('');
        }

        async function loadOnline() {
            try {
                const res = await fetch('/api/players');
                cachedPlayers = await res.json();
                renderOnline((document.getElementById('searchFilter').value || '').trim().toLowerCase());
            } catch (e) { console.error(e); }
        }

        function renderOnline(query) {
            const tbody = document.getElementById('onlineTbody');
            const filtered = cachedPlayers.filter(p => {
                if (!query) return true;
                return (p.nickname || '').toLowerCase().includes(query) ||
                       (p.steamId || '').toLowerCase().includes(query) ||
                       (p.hwid || '').toLowerCase().includes(query);
            });

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">В данный момент игроки не найдены.</td></tr>';
                return;
            }

            tbody.innerHTML = filtered.map(p => \`
                <tr>
                    <td><span class="badge \${p.active ? 'badge-active' : 'badge-blocked'}"><span class="pulse-dot"></span> \${p.active ? 'В ИГРЕ' : 'ВЫШЕЛ'}</span></td>
                    <td style="font-weight: 700; color: #fff; font-size: 15px;">\${escapeHtml(p.nickname)}</td>
                    <td class="mono" style="color: var(--cyan-neon); font-weight: 600;">\${p.steamId !== '0' ? p.steamId : 'No-Steam'}</td>
                    <td class="mono" style="font-size: 11px; color: var(--text-muted);">\${p.hwid || 'N/A'}</td>
                    <td>\${p.secondsAgo} сек.</td>
                    <td><button class="btn-action" style="padding: 5px 12px; font-size: 12px;" onclick="requestScreen('\${p.steamId}')">📸 Скриншот</button></td>
                </tr>
            \`).join('');
        }

        function openProfileModal() {
            document.getElementById('profileUser').value = document.getElementById('currentAdminName').innerText;
            document.getElementById('profilePass').value = '';
            document.getElementById('profileError').style.display = 'none';
            document.getElementById('profileSuccess').style.display = 'none';
            document.getElementById('profileModal').style.display = 'flex';
        }
        function closeProfileModal() { document.getElementById('profileModal').style.display = 'none'; }

        async function submitProfileUpdate() {
            const nu = document.getElementById('profileUser').value.trim();
            const np = document.getElementById('profilePass').value.trim();
            const err = document.getElementById('profileError');
            const succ = document.getElementById('profileSuccess');
            err.style.display = 'none';
            succ.style.display = 'none';

            try {
                const res = await fetch('/api/admin/profile/update', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                    body: JSON.stringify({ newUsername: nu, newPassword: np })
                });
                const data = await res.json();
                if (data.success) {
                    succ.innerText = data.message;
                    succ.style.display = 'block';
                    document.getElementById('currentAdminName').innerText = data.username;
                    setTimeout(closeProfileModal, 1200);
                } else {
                    err.innerText = data.message;
                    err.style.display = 'block';
                }
            } catch (e) {
                err.innerText = 'Ошибка: ' + e;
                err.style.display = 'block';
            }
        }

        function openCreateUserModal() {
            document.getElementById('newUsername').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('createError').style.display = 'none';
            document.getElementById('createUserModal').style.display = 'flex';
        }
        function closeCreateUserModal() { document.getElementById('createUserModal').style.display = 'none'; }

        async function submitCreateUser() {
            const u = document.getElementById('newUsername').value.trim();
            const p = document.getElementById('newPassword').value.trim();
            const r = document.getElementById('newRole').value;
            const err = document.getElementById('createError');

            try {
                const res = await fetch('/api/admin/users/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                    body: JSON.stringify({ username: u, password: p, role: r })
                });
                const data = await res.json();
                if (data.success) {
                    closeCreateUserModal();
                    loadUsers();
                } else {
                    err.innerText = data.message;
                    err.style.display = 'block';
                }
            } catch (e) {
                err.innerText = 'Ошибка: ' + e;
                err.style.display = 'block';
            }
        }

        async function toggleUser(username) {
            try {
                await fetch('/api/admin/users/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                    body: JSON.stringify({ username })
                });
                loadUsers();
            } catch (e) { alert('Ошибка: ' + e); }
        }

        async function resetHwid(username) {
            if (!confirm('Сбросить привязку HWID для ' + username + '?')) return;
            try {
                await fetch('/api/admin/users/reset_hwid', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                    body: JSON.stringify({ username })
                });
                alert('HWID успешно сброшен!');
                loadUsers();
            } catch (e) { alert('Ошибка: ' + e); }
        }

        let targetResetUser = '';
        function openResetPassModal(username) {
            targetResetUser = username;
            document.getElementById('resetTargetUser').innerText = username;
            document.getElementById('resetNewPass').value = '';
            document.getElementById('resetError').style.display = 'none';
            document.getElementById('resetPassModal').style.display = 'flex';
        }
        function closeResetPassModal() { document.getElementById('resetPassModal').style.display = 'none'; }

        async function submitResetPassword() {
            const p = document.getElementById('resetNewPass').value.trim();
            const err = document.getElementById('resetError');
            try {
                const res = await fetch('/api/admin/users/reset_password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                    body: JSON.stringify({ username: targetResetUser, newPassword: p })
                });
                const data = await res.json();
                if (data.success) {
                    alert('Пароль успешно обновлён!');
                    closeResetPassModal();
                } else {
                    err.innerText = data.message;
                    err.style.display = 'block';
                }
            } catch (e) { err.innerText = 'Ошибка: ' + e; err.style.display = 'block'; }
        }

        async function deleteUser(username) {
            if (!confirm('Вы уверены, что хотите НАВСЕГДА удалить пользователя ' + username + '?')) return;
            try {
                await fetch('/api/admin/users/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                    body: JSON.stringify({ username })
                });
                loadUsers();
            } catch (e) { alert('Ошибка: ' + e); }
        }

        async function requestScreen(steamId) {
            try {
                await fetch('/api/screen_request', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: steamId })
                });
                alert('Запрос скрытого снимка экрана для ' + steamId + ' отправлен! Результат поступит в Discord.');
            } catch (e) { alert('Ошибка: ' + e); }
        }

        function escapeHtml(t) { return (t || '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

        checkAuth();
        setInterval(loadOnline, 4000);
    </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`[HeavyRustAuth] Server listening on port ${PORT}`);
});
