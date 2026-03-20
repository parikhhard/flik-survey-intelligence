'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// FLIK Survey Intelligence — Production Server
// AI  : Snowflake Cortex (claude-3-5-sonnet) — zero external API keys
// Auth: bcrypt login + express-session
// DB  : Snowflake key-pair (RSA JWT)
// ─────────────────────────────────────────────────────────────────────────────

require('dotenv').config();

const express   = require('express');
const session   = require('express-session');
const snowflake = require('snowflake-sdk');
const bcrypt    = require('bcrypt');
const crypto    = require('crypto');
const path      = require('path');
const helmet    = require('helmet');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(helmet({ contentSecurityPolicy: false }));

// ── Sessions ──────────────────────────────────────────────────────────────────
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
body{font-family:"DM Sans",sans-serif;background:#0F1A14;display:flex;align-items:center;justify-content:center;min-height:100vh;}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% -10%,rgba(64,145,108,0.18) 0%,transparent 70%);pointer-events:none;}
.card{background:rgba(255,254,249,0.04);backdrop-filter:blur(24px);border-radius:20px;padding:48px 44px 40px;width:420px;max-width:calc(100vw - 32px);box-shadow:0 0 0 1px rgba(64,145,108,0.18),0 32px 64px rgba(0,0,0,0.5);position:relative;z-index:1;}
.logo{display:flex;align-items:center;gap:13px;margin-bottom:36px;}
.lmark{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#1B4332,#40916C);display:flex;align-items:center;justify-content:center;}
.lmark svg{width:22px;height:22px;fill:white;}
.brand{font-family:"Playfair Display",serif;font-size:19px;font-weight:700;color:#D8F3DC;display:block;}
.sub{font-size:9px;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:#52B788;opacity:0.7;}
h1{font-family:"Playfair Display",serif;font-size:24px;font-weight:700;color:#F0FDF4;margin-bottom:6px;}
p.desc{font-size:13px;color:rgba(216,243,220,0.55);margin-bottom:28px;line-height:1.6;}
label{display:block;font-size:11px;font-weight:600;color:rgba(216,243,220,0.6);margin-bottom:6px;margin-top:18px;letter-spacing:.06em;text-transform:uppercase;}
input{width:100%;padding:12px 15px;border:1px solid rgba(64,145,108,0.25);border-radius:10px;font-family:"DM Sans",sans-serif;font-size:14px;color:#D8F3DC;outline:none;background:rgba(255,255,255,0.05);transition:all .18s;}
input::placeholder{color:rgba(216,243,220,0.25);}
input:focus{border-color:rgba(64,145,108,0.6);background:rgba(255,255,255,0.07);box-shadow:0 0 0 3px rgba(64,145,108,0.12);}
button{width:100%;padding:13px;border:none;border-radius:11px;background:linear-gradient(135deg,#1B4332,#2D6A4F);color:#D8F3DC;font-family:"DM Sans",sans-serif;font-size:14px;font-weight:600;cursor:pointer;margin-top:24px;transition:all .2s;box-shadow:0 4px 16px rgba(27,67,50,0.5);}
button:hover{background:linear-gradient(135deg,#2D6A4F,#40916C);transform:translateY(-1px);}
.error{background:rgba(231,111,81,0.15);border:1px solid rgba(231,111,81,0.35);border-radius:9px;padding:11px 14px;font-size:13px;color:#FCA5A5;margin-bottom:6px;}
.switch{text-align:center;margin-top:22px;font-size:13px;color:rgba(216,243,220,0.4);}
.switch a{color:#52B788;text-decoration:none;font-weight:600;}
.footer{text-align:center;margin-top:20px;font-size:10px;color:rgba(216,243,220,0.2);}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="lmark"><svg viewBox="0 0 24 24"><path d="M18.06 22.99h1.66c.84 0 1.53-.64 1.63-1.46L23 5.05h-5V1h-1.97v4.05h-4.97l.3 2.34c1.71.47 3.31 1.32 4.27 2.26 1.44 1.42 2.43 2.89 2.43 5.29v8.05zM1 21.99V21h15.03v.99c0 .55-.45 1-1.01 1H2.01c-.56 0-1.01-.45-1.01-1zm15.03-7c0-4.5-6.72-5.5-7.52-5.5-4.5 0-7.51 3.03-7.51 5.5v5h15.03v-5z"/></svg></div>
    <div><span class="brand">FLIK</span><span class="sub">Survey Intelligence</span></div>
  </div>
  <h1>Welcome back</h1>
  <p class="desc">Sign in to access FLIK analytics.</p>
  ${err}
  <form method="POST" action="/login">
    <label>Email</label>
    <input type="email" name="email" placeholder="you@compass-usa.com" autocomplete="email" required autofocus>
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="switch">Don't have an account? <a href="/signup">Sign up</a></div>
  <p class="footer">FLIK Hospitality Group -- Internal Analytics</p>
</div>
</body>
</html>`);
});

// ── Signup page ───────────────────────────────────────────────────────────────
app.get('/signup', function (req, res) {
  if (req.session && req.session.authenticated) return res.redirect('/');
  const errMsg = {
    domain:  'Only @compass-usa.com email addresses can register.',
    exists:  'An account with this email already exists.',
    weak:    'Password must be at least 8 characters.',
    mismatch:'Passwords do not match.',
    failed:  'Registration failed. Please try again.'
  }[req.query.error] || '';

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FLIK | Sign Up</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:"DM Sans",sans-serif;background:#0F1A14;display:flex;align-items:center;justify-content:center;min-height:100vh;}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% -10%,rgba(64,145,108,0.18) 0%,transparent 70%);pointer-events:none;}
.card{background:rgba(255,254,249,0.04);backdrop-filter:blur(24px);border-radius:20px;padding:48px 44px 40px;width:420px;max-width:calc(100vw - 32px);box-shadow:0 0 0 1px rgba(64,145,108,0.18),0 32px 64px rgba(0,0,0,0.5);position:relative;z-index:1;}
.logo{display:flex;align-items:center;gap:13px;margin-bottom:36px;}
.lmark{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#1B4332,#40916C);display:flex;align-items:center;justify-content:center;}
.lmark svg{width:22px;height:22px;fill:white;}
.brand{font-family:"Playfair Display",serif;font-size:19px;font-weight:700;color:#D8F3DC;display:block;}
.sub{font-size:9px;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:#52B788;opacity:0.7;}
h1{font-family:"Playfair Display",serif;font-size:24px;font-weight:700;color:#F0FDF4;margin-bottom:6px;}
p.desc{font-size:13px;color:rgba(216,243,220,0.55);margin-bottom:28px;line-height:1.6;}
label{display:block;font-size:11px;font-weight:600;color:rgba(216,243,220,0.6);margin-bottom:6px;margin-top:18px;letter-spacing:.06em;text-transform:uppercase;}
input{width:100%;padding:12px 15px;border:1px solid rgba(64,145,108,0.25);border-radius:10px;font-family:"DM Sans",sans-serif;font-size:14px;color:#D8F3DC;outline:none;background:rgba(255,255,255,0.05);transition:all .18s;}
input::placeholder{color:rgba(216,243,220,0.25);}
input:focus{border-color:rgba(64,145,108,0.6);background:rgba(255,255,255,0.07);box-shadow:0 0 0 3px rgba(64,145,108,0.12);}
button{width:100%;padding:13px;border:none;border-radius:11px;background:linear-gradient(135deg,#1B4332,#2D6A4F);color:#D8F3DC;font-family:"DM Sans",sans-serif;font-size:14px;font-weight:600;cursor:pointer;margin-top:24px;transition:all .2s;box-shadow:0 4px 16px rgba(27,67,50,0.5);}
button:hover{background:linear-gradient(135deg,#2D6A4F,#40916C);transform:translateY(-1px);}
.error{background:rgba(231,111,81,0.15);border:1px solid rgba(231,111,81,0.35);border-radius:9px;padding:11px 14px;font-size:13px;color:#FCA5A5;margin-bottom:6px;}
.success{background:rgba(64,145,108,0.15);border:1px solid rgba(64,145,108,0.35);border-radius:9px;padding:11px 14px;font-size:13px;color:#86EFAC;margin-bottom:6px;}
.switch{text-align:center;margin-top:22px;font-size:13px;color:rgba(216,243,220,0.4);}
.switch a{color:#52B788;text-decoration:none;font-weight:600;}
.hint{font-size:11px;color:rgba(82,183,136,0.55);margin-top:4px;}
.footer{text-align:center;margin-top:20px;font-size:10px;color:rgba(216,243,220,0.2);}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="lmark"><svg viewBox="0 0 24 24"><path d="M18.06 22.99h1.66c.84 0 1.53-.64 1.63-1.46L23 5.05h-5V1h-1.97v4.05h-4.97l.3 2.34c1.71.47 3.31 1.32 4.27 2.26 1.44 1.42 2.43 2.89 2.43 5.29v8.05zM1 21.99V21h15.03v.99c0 .55-.45 1-1.01 1H2.01c-.56 0-1.01-.45-1.01-1zm15.03-7c0-4.5-6.72-5.5-7.52-5.5-4.5 0-7.51 3.03-7.51 5.5v5h15.03v-5z"/></svg></div>
    <div><span class="brand">FLIK</span><span class="sub">Survey Intelligence</span></div>
  </div>
  <h1>Create account</h1>
  <p class="desc">Join the FLIK analytics platform.</p>
  ${errMsg ? `<div class="error">${errMsg}</div>` : ''}
  <form method="POST" action="/signup">
    <label>Full Name</label>
    <input type="text" name="fullname" placeholder="Hard Parikh" autocomplete="name" required autofocus>
    <label>Work Email</label>
    <input type="email" name="email" placeholder="you@compass-usa.com" autocomplete="email" required>
    <p class="hint">Must be a @compass-usa.com address</p>
    <label>Password</label>
    <input type="password" name="password" placeholder="Min. 8 characters" autocomplete="new-password" required>
    <label>Confirm Password</label>
    <input type="password" name="confirm" placeholder="Repeat password" autocomplete="new-password" required>
    <button type="submit">Create Account</button>
  </form>
  <div class="switch">Already have an account? <a href="/login">Sign in</a></div>
  <p class="footer">FLIK Hospitality Group -- Internal Analytics</p>
</div>
</body>
</html>`);
});

app.post('/signup', async function (req, res) {
  const fullname = (req.body.fullname || '').trim();
  const email    = (req.body.email    || '').trim().toLowerCase();
  const password =  req.body.password || '';
  const confirm  =  req.body.confirm  || '';
  const ALLOWED_DOMAIN = (process.env.ALLOWED_DOMAIN || 'compass-usa.com').toLowerCase();

  if (!email.endsWith('@' + ALLOWED_DOMAIN)) return res.redirect('/signup?error=domain');
  if (password.length < 8)                   return res.redirect('/signup?error=weak');
  if (password !== confirm)                  return res.redirect('/signup?error=mismatch');

  try {
    const existing = await dbGetUser(email);
    if (existing) return res.redirect('/signup?error=exists');
    const hash = await bcrypt.hash(password, 12);
    await dbCreateUser(email, fullname, hash);
    res.redirect('/login?msg=registered');
  } catch (e) {
    console.error('[Signup]', e.message);
    res.redirect('/signup?error=failed');
  }
});

app.post('/login', async function (req, res) {
  const email    = (req.body.email    || '').trim().toLowerCase();
  const password =  req.body.password || '';
  const ALLOWED_DOMAIN = (process.env.ALLOWED_DOMAIN || 'compass-usa.com').toLowerCase();

  if (!email || !password)                   return res.redirect('/login?error=1');
  if (!email.endsWith('@' + ALLOWED_DOMAIN)) return res.redirect('/login?error=1');

  try {
    const user = await dbGetUser(email);
    if (!user) return res.redirect('/login?error=1');
    const match = await bcrypt.compare(password, user.PASSWORD_HASH);
    if (!match) return res.redirect('/login?error=1');
    req.session.authenticated = true;
    req.session.user = { email: user.EMAIL, name: user.FULL_NAME || email.split('@')[0] };
    res.redirect('/');
  } catch (e) {
    console.error('[Login]', e.message);
    res.redirect('/login?error=1');
  }
});

app.get('/logout', function (req, res) {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/api/me', requireAuth, function (req, res) {
  res.json({ email: req.session.user.email, name: req.session.user.name });
});

// ── Snowflake connection ──────────────────────────────────────────────────────
// Create a fresh connection for every request.
// Cortex queries are long-running and the SDK connection becomes unreliable
// after the first Cortex call. Fresh connections are the simplest fix.

function buildConnOptions() {
  const opts = {
    account:        process.env.SNOWFLAKE_ACCOUNT   || 'uya38094.us-east-1.snowflakecomputing.com',
    username:       process.env.SNOWFLAKE_USERNAME  || 'PARIKH01_SRV',
    warehouse:      process.env.SNOWFLAKE_WAREHOUSE || 'E15_ANA_WH',
    role:           process.env.SNOWFLAKE_ROLE      || 'E15_SRV_DBT',
    database:       'FLIK_ANALYTICS',
    schema:         'CURIOSITY_WIDGETS',
    loginTimeout:   30,
    networkTimeout: 120000
  };

  if (process.env.SNOWFLAKE_PRIVATE_KEY) {
    const pk = crypto.createPrivateKey({ key: process.env.SNOWFLAKE_PRIVATE_KEY, format: 'pem' });
    opts.authenticator = 'SNOWFLAKE_JWT';
    opts.privateKey    = pk.export({ format: 'pem', type: 'pkcs8' });
  } else if (process.env.SNOWFLAKE_PASSWORD) {
    opts.password = process.env.SNOWFLAKE_PASSWORD;
  } else {
    throw new Error('No Snowflake auth configured.');
  }
  return opts;
}

function sfQuery(sql, callback) {
  let opts;
  try { opts = buildConnOptions(); }
  catch (e) { return callback(e); }

  const conn = snowflake.createConnection(opts);
  conn.connect(function (err, c) {
    if (err) {
      console.error('[Snowflake] Connect error:', err.message);
      return callback(err);
    }
    c.execute({
      sqlText:  sql,
      complete: function (qErr, stmt, rows) {
        // Always destroy connection when done
        try { c.destroy(function(){}); } catch(e) {}
        if (qErr) return callback(qErr);
        callback(null, rows);
      }
    });
  });
}

// ── Bootstrap user table ──────────────────────────────────────────────────────
function bootstrapUserTable() {
  sfQuery(`
    CREATE TABLE IF NOT EXISTS FLIK_ANALYTICS.CURIOSITY_WIDGETS.APP_USERS (
      EMAIL         VARCHAR(255) PRIMARY KEY,
      FULL_NAME     VARCHAR(255),
      PASSWORD_HASH VARCHAR(255),
      IS_ACTIVE     BOOLEAN DEFAULT TRUE,
      CREATED_AT    TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
      LAST_LOGIN_AT TIMESTAMP_NTZ
    )
  `, function (err) {
    if (err) console.error('[Bootstrap] Table error:', err.message);
    else     console.log('[Bootstrap] APP_USERS ready.');
  });
}

// ── User helpers ──────────────────────────────────────────────────────────────
function dbGetUser(email) {
  return new Promise(function (resolve, reject) {
    const e = email.replace(/'/g, "''");
    sfQuery(
      `SELECT * FROM FLIK_ANALYTICS.CURIOSITY_WIDGETS.APP_USERS WHERE EMAIL = '${e}' LIMIT 1`,
      function (err, rows) {
        if (err) return reject(err);
        resolve(rows && rows.length ? rows[0] : null);
      }
    );
  });
}

function dbCreateUser(email, fullname, hash) {
  return new Promise(function (resolve, reject) {
    const e = email.replace(/'/g, "''");
    const n = fullname.replace(/'/g, "''");
    sfQuery(
      `INSERT INTO FLIK_ANALYTICS.CURIOSITY_WIDGETS.APP_USERS (EMAIL, FULL_NAME, PASSWORD_HASH, IS_ACTIVE)
       VALUES ('${e}', '${n}', '${hash}', TRUE)`,
      function (err) { if (err) reject(err); else resolve(); }
    );
  });
}

// ── Survey data endpoint ──────────────────────────────────────────────────────
app.get('/api/survey-data', requireAuth, function (req, res) {
  var sql = [
    'SELECT',
    '  RESPONSE_ID,',
    '  UNIT_SAP_NUMBER,',
    '  UNIT                    AS UNIT_NAME,',
    '  ANALYTICS_QUESTION_TEXT,',
    '  CSAT,',
    '  CSAT_REASON',
    'FROM FLIK_ANALYTICS.CURIOSITY_WIDGETS.RESPONSES',
    'WHERE CSAT_REASON IS NOT NULL',
    '  AND CSAT IS NOT NULL',
    'ORDER BY UNIT_SAP_NUMBER'
  ].join('\n');

  sfQuery(sql, function (err, rows) {
    if (err) {
      console.error('[Survey Data]', err.message);
      return res.status(500).json({ error: 'Query failed: ' + err.message });
    }
    var out = rows.map(function (r) {
      return {
        response_id:             String(r.RESPONSE_ID               || ''),
        unit_sap_number:         String(r.UNIT_SAP_NUMBER           || ''),
        unit:                    String(r.UNIT_NAME                 || ''),
        analytics_question_text: String(r.ANALYTICS_QUESTION_TEXT   || ''),
        csat:                    parseFloat(r.CSAT)                 || 0,
        csat_reason:             String(r.CSAT_REASON               || '')
      };
    });
    console.log('[Survey Data] ' + out.length + ' rows -> ' + req.session.user.email);
    res.json(out);
  });
});

// ── AI endpoint — Snowflake Cortex ────────────────────────────────────────────
app.post('/api/chat', requireAuth, function (req, res) {
  const { system, messages } = req.body;
  if (!messages || !Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: 'messages array required.' });
  }

  let conversation = (system || '') + '\n\n';
  messages.slice(-8).forEach(function (m) {
    conversation += m.role.toUpperCase() + ': ' + m.content + '\n\n';
  });
  conversation += 'ASSISTANT:';

  const escaped = conversation.replace(/\\/g, '\\\\').replace(/'/g, "''");
  const sql     = "SELECT SNOWFLAKE.CORTEX.COMPLETE('claude-3-5-sonnet', '" + escaped + "') AS RESPONSE";

  sfQuery(sql, function (queryErr, rows) {
    if (queryErr) {
      console.error('[Cortex]', queryErr.message);
      return res.status(500).json({ error: 'Cortex failed: ' + queryErr.message });
    }
    const text = rows && rows[0] ? String(rows[0].RESPONSE || '') : '';
    res.json({
      content:     [{ type: 'text', text: text }],
      stop_reason: 'end_turn',
      _provider:   'snowflake-cortex'
    });
  });
});

// ── Static + frontend ─────────────────────────────────────────────────────────
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

app.use(function (req, res) {
  if (!req.session || !req.session.authenticated) return res.redirect('/login');
  res.status(404).send('Not found');
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log('FLIK Survey Intelligence on port ' + PORT + ' [' + (process.env.NODE_ENV || 'development') + ']');
  // Test connection on startup
  sfQuery('SELECT 1', function (err) {
    if (err) { console.error('[Startup] Snowflake test failed:', err.message); return; }
    console.log('[Startup] Snowflake OK.');
    bootstrapUserTable();
  });
});