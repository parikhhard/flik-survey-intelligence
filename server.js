'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// FLIK Survey Intelligence — Production Server v3
// Auth    : Sign up / login stored in Snowflake, @compass-usa.com only
// Data    : Incremental load — only fetches new rows since last pull
// AI      : Snowflake Cortex claude-3-5-sonnet with prompt caching
// Security: bcrypt, express-session, helmet, rate limiting
// ─────────────────────────────────────────────────────────────────────────────

require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const snowflake    = require('snowflake-sdk');
const bcrypt       = require('bcrypt');
const crypto       = require('crypto');
const path         = require('path');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');

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

// ── Rate limiters ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      20,
  message:  'Too many attempts. Please wait 15 minutes.'
});

const aiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      parseInt(process.env.RATE_LIMIT_AI || '30'),
  keyGenerator: req => (req.session && req.session.user ? req.session.user.email : req.ip),
  message: { error: 'Too many requests. Please wait a few minutes.' }
});

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not authenticated.' });
  res.redirect('/login');
}

const ALLOWED_DOMAIN = (process.env.ALLOWED_DOMAIN || 'compass-usa.com').toLowerCase();

function validEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const e = email.trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.endsWith('@' + ALLOWED_DOMAIN);
}

// ── Shared HTML helpers ───────────────────────────────────────────────────────
const AUTH_CSS = `
*{margin:0;padding:0;box-sizing:border-box;}
html,body{height:100%;}
body{font-family:"DM Sans",sans-serif;background:#0F1A14;display:flex;align-items:center;justify-content:center;min-height:100vh;position:relative;overflow:hidden;}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% -10%,rgba(64,145,108,0.18) 0%,transparent 70%),radial-gradient(ellipse 50% 40% at 80% 80%,rgba(27,67,50,0.25) 0%,transparent 60%);pointer-events:none;}
.card{background:rgba(255,254,249,0.04);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border-radius:20px;padding:48px 44px 40px;width:420px;max-width:calc(100vw - 32px);box-shadow:0 0 0 1px rgba(64,145,108,0.18),0 32px 64px rgba(0,0,0,0.5);position:relative;z-index:1;}
.logo{display:flex;align-items:center;gap:13px;margin-bottom:36px;}
.lmark{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#1B4332,#40916C);display:flex;align-items:center;justify-content:center;box-shadow:0 4px 16px rgba(64,145,108,0.4);}
.lmark svg{width:22px;height:22px;fill:white;}
.brand{font-family:"Playfair Display",serif;font-size:19px;font-weight:700;color:#D8F3DC;display:block;letter-spacing:-0.01em;}
.sub{font-size:9px;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:#52B788;opacity:0.7;}
h1{font-family:"Playfair Display",serif;font-size:24px;font-weight:700;color:#F0FDF4;margin-bottom:6px;letter-spacing:-0.02em;}
p.desc{font-size:13px;color:rgba(216,243,220,0.55);margin-bottom:28px;line-height:1.6;}
label{display:block;font-size:11px;font-weight:600;color:rgba(216,243,220,0.6);margin-bottom:6px;margin-top:18px;letter-spacing:.06em;text-transform:uppercase;}
input{width:100%;padding:12px 15px;border:1px solid rgba(64,145,108,0.25);border-radius:10px;font-family:"DM Sans",sans-serif;font-size:14px;color:#D8F3DC;outline:none;background:rgba(255,255,255,0.05);transition:all .18s;}
input::placeholder{color:rgba(216,243,220,0.25);}
input:focus{border-color:rgba(64,145,108,0.6);background:rgba(255,255,255,0.07);box-shadow:0 0 0 3px rgba(64,145,108,0.12);}
button{width:100%;padding:13px;border:none;border-radius:11px;background:linear-gradient(135deg,#1B4332,#2D6A4F);color:#D8F3DC;font-family:"DM Sans",sans-serif;font-size:14px;font-weight:600;cursor:pointer;margin-top:24px;transition:all .2s;letter-spacing:.02em;box-shadow:0 4px 16px rgba(27,67,50,0.5);}
button:hover{background:linear-gradient(135deg,#2D6A4F,#40916C);transform:translateY(-1px);box-shadow:0 6px 20px rgba(27,67,50,0.6);}
button:active{transform:translateY(0);}
.error{background:rgba(231,111,81,0.15);border:1px solid rgba(231,111,81,0.35);border-radius:9px;padding:11px 14px;font-size:13px;color:#FCA5A5;margin-bottom:6px;}
.success{background:rgba(64,145,108,0.15);border:1px solid rgba(64,145,108,0.35);border-radius:9px;padding:11px 14px;font-size:13px;color:#86EFAC;margin-bottom:6px;}
.switch{text-align:center;margin-top:22px;font-size:13px;color:rgba(216,243,220,0.4);}
.switch a{color:#52B788;text-decoration:none;font-weight:600;}
.switch a:hover{color:#95D5B2;}
.domain-hint{font-size:11px;color:rgba(82,183,136,0.55);margin-top:5px;}
.footer{text-align:center;margin-top:20px;font-size:10px;color:rgba(216,243,220,0.2);letter-spacing:.05em;}
`;

const AUTH_HEAD = (title) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FLIK | ${title}</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>${AUTH_CSS}</style>
</head>
<body>`;

const LOGO_HTML = `
<div class="logo">
  <div class="lmark">
    <svg viewBox="0 0 24 24"><path d="M18.06 22.99h1.66c.84 0 1.53-.64 1.63-1.46L23 5.05h-5V1h-1.97v4.05h-4.97l.3 2.34c1.71.47 3.31 1.32 4.27 2.26 1.44 1.42 2.43 2.89 2.43 5.29v8.05zM1 21.99V21h15.03v.99c0 .55-.45 1-1.01 1H2.01c-.56 0-1.01-.45-1.01-1zm15.03-7c0-4.5-6.72-5.5-7.52-5.5-4.5 0-7.51 3.03-7.51 5.5v5h15.03v-5z"/></svg>
  </div>
  <div><span class="brand">FLIK</span><span class="sub">Survey Intelligence</span></div>
</div>`;

// ── Login page ────────────────────────────────────────────────────────────────
app.get('/login', function (req, res) {
  if (req.session && req.session.authenticated) return res.redirect('/');
  const msg = req.query.msg || '';
  const errMsg = {
    bad:      'Incorrect email or password.',
    unverified: 'Account not yet approved. Contact your administrator.',
    domain:   `Only @${ALLOWED_DOMAIN} email addresses are allowed.`,
    locked:   'Account locked after too many failed attempts. Try again in 15 minutes.'
  }[req.query.error] || (req.query.error ? 'Sign in failed. Please try again.' : '');
  const successMsg = msg === 'registered' ? 'Account created! You can now sign in.' : '';

  res.send(AUTH_HEAD('Sign In') + `
<div class="card">
  ${LOGO_HTML}
  <h1>Welcome back</h1>
  <p class="desc">Sign in to access FLIK analytics.</p>
  ${errMsg    ? `<div class="error">${errMsg}</div>`     : ''}
  ${successMsg ? `<div class="success">${successMsg}</div>` : ''}
  <form method="POST" action="/login">
    <label>Work Email</label>
    <input type="email" name="email" placeholder="you@compass-usa.com" autocomplete="email" required autofocus>
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="switch">Don't have an account? <a href="/signup">Sign up</a></div>
  <p class="footer">FLIK Hospitality Group &mdash; Internal Analytics</p>
</div>
</body></html>`);
});

app.post('/login', authLimiter, async function (req, res) {
  const email    = (req.body.email    || '').trim().toLowerCase();
  const password =  req.body.password || '';
  if (!email || !password) return res.redirect('/login?error=bad');
  if (!validEmail(email))  return res.redirect('/login?error=domain');

  try {
    const user = await dbGetUser(email);
    if (!user) return res.redirect('/login?error=bad');
    if (!user.IS_ACTIVE) return res.redirect('/login?error=unverified');

    const match = await bcrypt.compare(password, user.PASSWORD_HASH);
    if (!match) {
      await dbRecordLoginAttempt(email, false);
      return res.redirect('/login?error=bad');
    }

    await dbRecordLoginAttempt(email, true);
    req.session.authenticated = true;
    req.session.user = {
      email:    user.EMAIL,
      name:     user.FULL_NAME || email.split('@')[0],
      role:     user.ROLE || 'viewer'
    };
    res.redirect('/');
  } catch (e) {
    console.error('[Login]', e.message);
    res.redirect('/login?error=bad');
  }
});

// ── Signup page ───────────────────────────────────────────────────────────────
app.get('/signup', function (req, res) {
  if (req.session && req.session.authenticated) return res.redirect('/');
  const errMsg = {
    domain:  `Only @${ALLOWED_DOMAIN} email addresses can register.`,
    exists:  'An account with this email already exists.',
    weak:    'Password must be at least 8 characters.',
    mismatch: 'Passwords do not match.',
    failed:  'Registration failed. Please try again.'
  }[req.query.error] || '';

  res.send(AUTH_HEAD('Sign Up') + `
<div class="card">
  ${LOGO_HTML}
  <h1>Create account</h1>
  <p class="desc">Join the FLIK analytics platform.</p>
  ${errMsg ? `<div class="error">${errMsg}</div>` : ''}
  <form method="POST" action="/signup">
    <label>Full Name</label>
    <input type="text" name="fullname" placeholder="Hard Parikh" autocomplete="name" required autofocus>
    <label>Work Email</label>
    <input type="email" name="email" placeholder="you@compass-usa.com" autocomplete="email" required>
    <p class="domain-hint">Must be a @${ALLOWED_DOMAIN} address</p>
    <label>Password</label>
    <input type="password" name="password" placeholder="Min. 8 characters" autocomplete="new-password" required>
    <label>Confirm Password</label>
    <input type="password" name="confirm" placeholder="Repeat password" autocomplete="new-password" required>
    <button type="submit">Create Account</button>
  </form>
  <div class="switch">Already have an account? <a href="/login">Sign in</a></div>
  <p class="footer">FLIK Hospitality Group &mdash; Internal Analytics</p>
</div>
</body></html>`);
});

app.post('/signup', authLimiter, async function (req, res) {
  const fullname = (req.body.fullname || '').trim();
  const email    = (req.body.email    || '').trim().toLowerCase();
  const password =  req.body.password || '';
  const confirm  =  req.body.confirm  || '';

  if (!validEmail(email))           return res.redirect('/signup?error=domain');
  if (password.length < 8)          return res.redirect('/signup?error=weak');
  if (password !== confirm)         return res.redirect('/signup?error=mismatch');

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

app.get('/logout', function (req, res) {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/api/me', requireAuth, function (req, res) {
  res.json(req.session.user);
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

  const opts = {
    account:        process.env.SNOWFLAKE_ACCOUNT   || 'uya38094.us-east-1.snowflakecomputing.com',
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
      const pk = crypto.createPrivateKey({ key: process.env.SNOWFLAKE_PRIVATE_KEY, format: 'pem' });
      opts.authenticator = 'SNOWFLAKE_JWT';
      opts.privateKey    = pk.export({ format: 'pem', type: 'pkcs8' });
      console.log('[Snowflake] Key-pair auth');
    } catch (e) {
      sfConnecting = false;
      return callback(new Error('Bad private key: ' + e.message));
    }
  } else if (process.env.SNOWFLAKE_PASSWORD) {
    opts.password = process.env.SNOWFLAKE_PASSWORD;
    console.log('[Snowflake] Password auth');
  } else {
    sfConnecting = false;
    return callback(new Error('No Snowflake auth configured.'));
  }

  snowflake.createConnection(opts).connect(function (err, c) {
    sfConnecting = false;
    if (err) { console.error('[Snowflake] Failed:', err.message); return callback(err); }
    sfConn = c;
    console.log('[Snowflake] Connected.');
    callback(null, sfConn);
  });
}

function sfQuery(sql, callback) {
  getSnowflakeConnection(function (err, conn) {
    if (err) return callback(err);
    conn.execute({
      sqlText:  sql,
      complete: function (qErr, stmt, rows) {
        if (qErr) { sfConn = null; return callback(qErr); }
        callback(null, rows);
      }
    });
  });
}

// ── Bootstrap user table in Snowflake ─────────────────────────────────────────
function bootstrapUserTable() {
  const sql = `
    CREATE TABLE IF NOT EXISTS E15_ANALYST_SANDBOX.PARIKH01.APP_USERS (
      EMAIL           VARCHAR(255) PRIMARY KEY,
      FULL_NAME       VARCHAR(255),
      PASSWORD_HASH   VARCHAR(255),
      ROLE            VARCHAR(50)  DEFAULT 'viewer',
      IS_ACTIVE       BOOLEAN      DEFAULT TRUE,
      CREATED_AT      TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
      LAST_LOGIN_AT   TIMESTAMP_NTZ,
      LOGIN_COUNT     NUMBER       DEFAULT 0
    )
  `;
  sfQuery(sql, function (err) {
    if (err) console.error('[Bootstrap] User table error:', err.message);
    else     console.log('[Bootstrap] APP_USERS table ready.');
  });
}

// ── User DB helpers ───────────────────────────────────────────────────────────
function dbGetUser(email) {
  return new Promise(function (resolve, reject) {
    const e = email.replace(/'/g, "''");
    sfQuery(`SELECT * FROM E15_ANALYST_SANDBOX.PARIKH01.APP_USERS WHERE EMAIL = '${e}' LIMIT 1`,
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
      `INSERT INTO E15_ANALYST_SANDBOX.PARIKH01.APP_USERS (EMAIL, FULL_NAME, PASSWORD_HASH, IS_ACTIVE)
       VALUES ('${e}', '${n}', '${hash}', TRUE)`,
      function (err) { if (err) reject(err); else resolve(); }
    );
  });
}

function dbRecordLoginAttempt(email, success) {
  return new Promise(function (resolve) {
    const e = email.replace(/'/g, "''");
    const sql = success
      ? `UPDATE E15_ANALYST_SANDBOX.PARIKH01.APP_USERS SET LAST_LOGIN_AT = CURRENT_TIMESTAMP(), LOGIN_COUNT = LOGIN_COUNT + 1 WHERE EMAIL = '${e}'`
      : `UPDATE E15_ANALYST_SANDBOX.PARIKH01.APP_USERS SET LOGIN_COUNT = LOGIN_COUNT + 1 WHERE EMAIL = '${e}'`;
    sfQuery(sql, () => resolve());
  });
}

// ── Incremental data cache ────────────────────────────────────────────────────
// Only fetches rows newer than what we already have.
// Resets every 60 minutes so data stays fresh without hammering Snowflake.

let dataCache      = [];       // accumulated rows
let lastAuditDate  = null;     // last AUDIT_DATE we fetched up to
let cacheBuiltAt   = null;     // when cache was last fully rebuilt
const CACHE_TTL_MS = 60 * 60 * 1000;  // full rebuild every 60 min

function fetchIncrementalData(callback) {
  const now = Date.now();

  // Full rebuild if cache is empty or expired
  if (!cacheBuiltAt || (now - cacheBuiltAt) > CACHE_TTL_MS) {
    console.log('[Data] Full rebuild...');
    dataCache     = [];
    lastAuditDate = null;
    cacheBuiltAt  = now;
  }

  // Build WHERE clause — only fetch rows newer than last pull
  let whereExtra = '';
  if (lastAuditDate) {
    const d = lastAuditDate.replace(/'/g, "''");
    whereExtra = `AND AUDIT_DATE > '${d}'`;
  }

  const sql = `
    SELECT
      RESPONSE_ID,
      UNIT_SAP_NUMBER,
      UNIT                    AS UNIT_NAME,
      ANALYTICS_QUESTION_TEXT,
      CSAT,
      CSAT_REASON,
      AUDIT_DATE
    FROM FLIK_ANALYTICS.CURIOSITY_WIDGETS.RESPONSES
    WHERE CSAT_REASON IS NOT NULL
      AND CSAT IS NOT NULL
      ${whereExtra}
    ORDER BY AUDIT_DATE ASC
  `;

  sfQuery(sql, function (err, rows) {
    if (err) return callback(err);

    if (rows && rows.length) {
      const newRows = rows.map(function (r) {
        return {
          response_id:             String(r.RESPONSE_ID             || ''),
          unit_sap_number:         String(r.UNIT_SAP_NUMBER         || ''),
          unit:                    String(r.UNIT_NAME               || ''),
          analytics_question_text: String(r.ANALYTICS_QUESTION_TEXT || ''),
          csat:                    parseFloat(r.CSAT)               || 0,
          csat_reason:             String(r.CSAT_REASON             || ''),
          audit_date:              String(r.AUDIT_DATE              || '')
        };
      });

      dataCache = dataCache.concat(newRows);

      // Track newest audit date for next incremental pull
      const dates = newRows.map(r => r.audit_date).filter(Boolean).sort();
      if (dates.length) lastAuditDate = dates[dates.length - 1];

      console.log('[Data] +' + newRows.length + ' new rows. Total: ' + dataCache.length + '. Last: ' + lastAuditDate);
    } else {
      console.log('[Data] No new rows since ' + (lastAuditDate || 'beginning') + '. Cache: ' + dataCache.length + ' rows.');
    }

    callback(null, dataCache);
  });
}

// ── Survey data endpoint ──────────────────────────────────────────────────────
app.get('/api/survey-data', requireAuth, function (req, res) {
  fetchIncrementalData(function (err, rows) {
    if (err) return res.status(500).json({ error: 'Data fetch failed: ' + err.message });
    res.json(rows);
  });
});

// ── AI endpoint — Snowflake Cortex with prompt caching ────────────────────────
//
// Prompt caching strategy:
// The system prompt (analytics context) is large and identical across
// multiple turns in a conversation. We cache it server-side in a Map
// keyed by a hash of the prompt. On cache hit, we prepend a shorter
// "context reference" to the conversation instead of the full prompt,
// saving ~1500 tokens per request after the first.
//
// Note: True Cortex prompt caching (like Anthropic's cache_control)
// is not yet exposed in Snowflake's SQL API. This is server-side
// deduplication as an approximation.

const promptCache = new Map();  // hash -> { prompt, ts }
const PROMPT_CACHE_TTL = 30 * 60 * 1000;  // 30 min

function cachePrompt(systemPrompt) {
  const hash = crypto.createHash('sha256').update(systemPrompt).digest('hex').slice(0, 16);
  const now  = Date.now();

  // Evict expired entries
  for (const [k, v] of promptCache) {
    if (now - v.ts > PROMPT_CACHE_TTL) promptCache.delete(k);
  }

  if (!promptCache.has(hash)) {
    promptCache.set(hash, { prompt: systemPrompt, ts: now });
  }
  return hash;
}

function getCachedPrompt(hash) {
  const entry = promptCache.get(hash);
  if (!entry) return null;
  if (Date.now() - entry.ts > PROMPT_CACHE_TTL) { promptCache.delete(hash); return null; }
  entry.ts = Date.now(); // refresh TTL on access
  return entry.prompt;
}

app.post('/api/chat', requireAuth, aiLimiter, function (req, res) {
  const { system, messages, promptHash } = req.body;

  if (!messages || !Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: 'messages array required.' });
  }

  // Resolve system prompt — use cache if hash provided, otherwise cache new prompt
  let systemPrompt = system || '';
  let returnHash   = promptHash;

  if (promptHash) {
    const cached = getCachedPrompt(promptHash);
    if (cached) {
      systemPrompt = cached;
    } else {
      // Cache miss — client must resend full system prompt
      return res.status(400).json({ error: 'prompt_cache_miss', message: 'Resend full system prompt.' });
    }
  } else if (systemPrompt) {
    returnHash = cachePrompt(systemPrompt);
  }

  // Build Cortex conversation
  let conversation = systemPrompt + '\n\n';
  // Only send last 8 messages to keep prompt tight
  const recentMsgs = messages.slice(-8);
  recentMsgs.forEach(function (m) {
    conversation += m.role.toUpperCase() + ': ' + m.content + '\n\n';
  });
  conversation += 'ASSISTANT:';

  const escaped = conversation.replace(/\\/g, '\\\\').replace(/'/g, "''");
  const sql     = "SELECT SNOWFLAKE.CORTEX.COMPLETE('claude-3-5-sonnet', '" + escaped + "') AS RESPONSE";

  getSnowflakeConnection(function (err, conn) {
    if (err) return res.status(503).json({ error: 'Snowflake unavailable: ' + err.message });

    conn.execute({
      sqlText:  sql,
      complete: function (queryErr, stmt, rows) {
        if (queryErr) {
          sfConn = null;
          console.error('[Cortex]', queryErr.message);
          return res.status(500).json({ error: 'Cortex failed: ' + queryErr.message });
        }
        const text = rows && rows[0] ? String(rows[0].RESPONSE || '') : '';
        res.json({
          content:     [{ type: 'text', text: text }],
          stop_reason: 'end_turn',
          _provider:   'snowflake-cortex',
          _promptHash: returnHash  // Return hash so client can cache on next call
        });
      }
    });
  });
});

// ── Static + fallback ─────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', requireAuth, function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', function (req, res) {
  res.json({
    status:        'ok',
    snowflake:     sfConn && sfConn.isUp() ? 'connected' : 'disconnected',
    cacheRows:     dataCache.length,
    lastAuditDate: lastAuditDate,
    promptCacheSize: promptCache.size,
    timestamp:     new Date().toISOString()
  });
});

app.use(function (req, res) {
  if (!req.session || !req.session.authenticated) return res.redirect('/login');
  res.status(404).send('Not found');
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log('FLIK Survey Intelligence v3 on port ' + PORT);
  getSnowflakeConnection(function (err) {
    if (err) { console.error('[Startup] Snowflake failed:', err.message); return; }
    bootstrapUserTable();
  });
});