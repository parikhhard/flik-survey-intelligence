'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// FLIK Survey Intelligence — Production Server
// AI  : Snowflake Cortex (claude-3-5-sonnet) — zero external API keys
// Auth: bcrypt login + express-session
// DB  : Snowflake key-pair (RSA JWT) — no SSO, works on any server
// ─────────────────────────────────────────────────────────────────────────────

require('dotenv').config();

const express   = require('express');
const session   = require('express-session');
const snowflake = require('snowflake-sdk');
const bcrypt    = require('bcrypt');
const crypto    = require('crypto');
const path      = require('path');

const app = express();

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Helmet — disable CSP so inline JS works ───────────────────────────────────
const helmet = require('helmet');
app.use(helmet({ contentSecurityPolicy: false }));

// ── Sessions ──────────────────────────────────────────────────────────────────
app.set('trust proxy', 1);

app.use(session({
  secret:            process.env.SESSION_SECRET || 'flik-change-this-secret',
  resave:            false,
  saveUninitialized: false,
  proxy:             true,
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge:   8 * 60 * 60 * 1000
  }
}));

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not authenticated.' });
  res.redirect('/login');
}

// ── Login page ────────────────────────────────────────────────────────────────
app.get('/login', function (req, res) {
  if (req.session && req.session.authenticated) return res.redirect('/');
  const err = req.query.error ? '<div class="error">Incorrect username or password.</div>' : '';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FLIK | Sign In</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:"DM Sans",sans-serif;background:#FAF7F2;display:flex;align-items:center;justify-content:center;min-height:100vh;}
.card{background:#FFFEF9;border-radius:18px;padding:48px 40px 40px;width:380px;max-width:calc(100vw - 32px);box-shadow:0 8px 40px rgba(15,15,16,0.12);border:1px solid rgba(45,106,79,0.13);}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:32px;}
.lmark{width:42px;height:42px;border-radius:11px;background:linear-gradient(135deg,#1B4332,#40916C);display:flex;align-items:center;justify-content:center;}
.lmark svg{width:22px;height:22px;fill:white;}
.brand{font-family:"Playfair Display",serif;font-size:20px;font-weight:700;color:#1B4332;display:block;}
.sub{font-size:10px;font-weight:600;letter-spacing:.15em;text-transform:uppercase;color:#9CA3AF;}
h1{font-family:"Playfair Display",serif;font-size:22px;font-weight:700;color:#1C1C1E;margin-bottom:6px;}
p.desc{font-size:13px;color:#6B7280;margin-bottom:28px;line-height:1.5;}
label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px;margin-top:14px;}
input{width:100%;padding:11px 14px;border:1.5px solid rgba(45,106,79,0.22);border-radius:9px;font-family:"DM Sans",sans-serif;font-size:14px;color:#1C1C1E;outline:none;background:#FAF7F2;transition:border-color .18s;}
input:focus{border-color:#40916C;box-shadow:0 0 0 3px rgba(64,145,108,0.1);}
button{width:100%;padding:12px;border:none;border-radius:10px;background:linear-gradient(135deg,#1B4332,#40916C);color:white;font-family:"DM Sans",sans-serif;font-size:15px;font-weight:600;cursor:pointer;margin-top:22px;transition:opacity .18s;}
button:hover{opacity:0.9;}
.error{background:#FEE2E2;border:1px solid #FECACA;border-radius:8px;padding:10px 14px;font-size:13px;color:#991B1B;margin-bottom:18px;}
.footer{text-align:center;margin-top:24px;font-size:11px;color:#9CA3AF;}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="lmark">
      <svg viewBox="0 0 24 24"><path d="M18.06 22.99h1.66c.84 0 1.53-.64 1.63-1.46L23 5.05h-5V1h-1.97v4.05h-4.97l.3 2.34c1.71.47 3.31 1.32 4.27 2.26 1.44 1.42 2.43 2.89 2.43 5.29v8.05zM1 21.99V21h15.03v.99c0 .55-.45 1-1.01 1H2.01c-.56 0-1.01-.45-1.01-1zm15.03-7c0-4.5-6.72-5.5-7.52-5.5-4.5 0-7.51 3.03-7.51 5.5v5h15.03v-5z"/></svg>
    </div>
    <div><span class="brand">FLIK</span><span class="sub">Survey Intelligence</span></div>
  </div>
  <h1>Welcome back</h1>
  <p class="desc">Sign in to access the analytics dashboard.</p>
  ${err}
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" autocomplete="username" required autofocus>
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
  <p class="footer">FLIK Hospitality Group &mdash; Internal Analytics</p>
</div>
</body>
</html>`);
});

app.post('/login', async function (req, res) {
  const username = (req.body.username || '').trim().toLowerCase();
  const password = req.body.password || '';
  if (!username || !password) return res.redirect('/login?error=1');

  let users = [];
  try { users = JSON.parse(process.env.APP_USERS || '[]'); }
  catch (e) { console.error('APP_USERS parse error:', e.message); return res.redirect('/login?error=1'); }

  const user = users.find(u => u.username.toLowerCase() === username);
  if (!user) return res.redirect('/login?error=1');

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.redirect('/login?error=1');

  req.session.authenticated = true;
  req.session.user = { username: user.username, name: user.name || user.username };
  res.redirect('/');
});

app.get('/logout', function (req, res) {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/api/me', requireAuth, function (req, res) {
  res.json({ username: req.session.user.username, name: req.session.user.name });
});

// ── Snowflake connection ──────────────────────────────────────────────────────
let sfConn       = null;
let sfConnecting = false;

function getSnowflakeConnection(callback) {
  if (sfConn && sfConn.isUp()) return callback(null, sfConn);
  if (sfConnecting) {
    setTimeout(() => getSnowflakeConnection(callback), 500);
    return;
  }
  sfConnecting = true;

  const connOptions = {
    account:        process.env.SNOWFLAKE_ACCOUNT   || 'uya38094.us-east-1',
    username:       process.env.SNOWFLAKE_USERNAME  || 'PARIKH01_SRV',
    warehouse:      process.env.SNOWFLAKE_WAREHOUSE || 'E15_ANA_WH',
    role:           process.env.SNOWFLAKE_ROLE      || 'E15_SRV_DBT',
    database:       'FLIK_ANALYTICS',
    schema:         'CURIOSITY_WIDGETS',
    loginTimeout:   30,
    networkTimeout: 60000
  };

  if (process.env.SNOWFLAKE_PRIVATE_KEY) {
    try {
      const pkObj = crypto.createPrivateKey({
        key:    process.env.SNOWFLAKE_PRIVATE_KEY,
        format: 'pem'
      });
      connOptions.authenticator = 'SNOWFLAKE_JWT';
      connOptions.privateKey    = pkObj.export({ format: 'pem', type: 'pkcs8' });
      console.log('[Snowflake] Using key-pair auth');
    } catch (e) {
      sfConnecting = false;
      return callback(new Error('Invalid SNOWFLAKE_PRIVATE_KEY: ' + e.message));
    }
  } else if (process.env.SNOWFLAKE_PASSWORD) {
    connOptions.password = process.env.SNOWFLAKE_PASSWORD;
    console.log('[Snowflake] Using password auth');
  } else {
    sfConnecting = false;
    return callback(new Error('No Snowflake auth configured. Set SNOWFLAKE_PRIVATE_KEY or SNOWFLAKE_PASSWORD.'));
  }

  const conn = snowflake.createConnection(connOptions);
  conn.connect(function (err, c) {
    sfConnecting = false;
    if (err) {
      console.error('[Snowflake] Connection failed:', err.message);
      return callback(err);
    }
    sfConn = c;
    console.log('[Snowflake] Connected successfully.');
    callback(null, sfConn);
  });
}

// ── AI endpoint — Snowflake Cortex ────────────────────────────────────────────
app.post('/api/chat', requireAuth, function (req, res) {
  const { system, messages } = req.body;

  if (!messages || !Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: 'messages array required.' });
  }

  // Build prompt string for Cortex
  let conversation = (system || '') + '\n\n';
  messages.forEach(function (m) {
    conversation += m.role.toUpperCase() + ': ' + m.content + '\n\n';
  });
  conversation += 'ASSISTANT:';

  // Escape single quotes for SQL
  const escaped = conversation.replace(/\\/g, '\\\\').replace(/'/g, "''");
  const sql     = "SELECT SNOWFLAKE.CORTEX.COMPLETE('claude-3-5-sonnet', '" + escaped + "') AS RESPONSE";

  getSnowflakeConnection(function (err, conn) {
    if (err) return res.status(503).json({ error: 'Snowflake unavailable: ' + err.message });

    conn.execute({
      sqlText:  sql,
      complete: function (queryErr, stmt, rows) {
        if (queryErr) {
          sfConn = null; // Reset so next request reconnects
          console.error('[Cortex] Query error:', queryErr.message);
          return res.status(500).json({ error: 'Cortex failed: ' + queryErr.message });
        }
        const text = rows && rows[0] ? String(rows[0].RESPONSE || '') : '';
        res.json({
          content:     [{ type: 'text', text: text }],
          stop_reason: 'end_turn',
          _provider:   'snowflake-cortex'
        });
      }
    });
  });
});


// ── Survey data endpoint ──────────────────────────────────────────────────────
app.get('/api/survey-data', requireAuth, function (req, res) {
  const sql = `
    SELECT
      RESPONSE_ID,
      UNIT_SAP_NUMBER,
      UNIT                    AS UNIT_NAME,
      ANALYTICS_QUESTION_TEXT AS ANALYTICS_QUESTION_TEXT,
      CSAT                    AS CSAT,
      CSAT_REASON             AS CSAT_REASON
    FROM FLIK_ANALYTICS.CURIOSITY_WIDGETS.RESPONSES
    WHERE CSAT_REASON IS NOT NULL
      AND CSAT IS NOT NULL
    ORDER BY UNIT_SAP_NUMBER
  `;

  getSnowflakeConnection(function (err, conn) {
    if (err) return res.status(503).json({ error: 'Snowflake unavailable: ' + err.message });

    conn.execute({
      sqlText:  sql,
      complete: function (queryErr, stmt, rows) {
        if (queryErr) {
          sfConn = null;
          console.error('[Survey Data] Query error:', queryErr.message);
          return res.status(500).json({ error: 'Query failed: ' + queryErr.message });
        }
        const out = rows.map(function (r) {
          return {
            response_id:             String(r.RESPONSE_ID      || ''),
            unit_sap_number:         String(r.UNIT_SAP_NUMBER  || ''),
            unit:                    String(r.UNIT_NAME        || ''),
            analytics_question_text: String(r.ANALYTICS_QUESTION_TEXT || ''),
            csat:                    parseFloat(r.CSAT)        || 0,
            csat_reason:             String(r.CSAT_REASON      || '')
          };
        });
        console.log('[Survey Data] Served ' + out.length + ' rows to ' + req.session.user.username);
        res.json(out);
      }
    });
  });
});

// ── Serve frontend ────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', requireAuth, function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', function (req, res) {
  res.json({
    status:    'ok',
    snowflake: sfConn && sfConn.isUp() ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  });
});

// ── 404 fallback ──────────────────────────────────────────────────────────────
app.use(function (req, res) {
  if (!req.session || !req.session.authenticated) return res.redirect('/login');
  res.status(404).send('Not found');
});

// ── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log('FLIK Survey Intelligence running on port ' + PORT + ' [' + (process.env.NODE_ENV || 'development') + ']');
  // Pre-connect to Snowflake on startup
  getSnowflakeConnection(function (err) {
    if (err) console.error('[Snowflake] Startup connection failed:', err.message);
  });
});
