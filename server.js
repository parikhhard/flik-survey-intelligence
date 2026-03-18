'use strict';

require('dotenv').config();

const express     = require('express');
const session     = require('express-session');
const snowflake   = require('snowflake-sdk');
const fetch       = require('node-fetch');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const morgan      = require('morgan');
const compression = require('compression');
const bcrypt      = require('bcrypt');
const path        = require('path');

// Session store — uses memory if USE_MEMORY_SESSIONS=true or MONGODB_URI is missing
let sessionStore = undefined;
if (process.env.USE_MEMORY_SESSIONS !== 'true' && process.env.MONGODB_URI) {
  const MongoStore = require('connect-mongo');
  sessionStore = MongoStore.create({ mongoUrl: process.env.MONGODB_URI });
}

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
      styleSrc:   ["'self'", "'unsafe-inline'", "fonts.googleapis.com", "fonts.gstatic.com"],
      fontSrc:    ["'self'", "fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:"],
      connectSrc: ["'self'"]
    }
  }
}));

app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret:            process.env.SESSION_SECRET || 'fallback-secret-change-me',
  resave:            false,
  saveUninitialized: false,
  store:             sessionStore,
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge:   8 * 60 * 60 * 1000
  }
}));

// Auth guard
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  req.session.returnTo = req.originalUrl;
  res.redirect('/login');
}

// Login page
app.get('/login', function(req, res) {
  if (req.session && req.session.authenticated) {
    return res.redirect('/');
  }
  var err = req.query.error;
  var errorHtml = '';
  if (err === 'bad')  { errorHtml = '<div class="error">Incorrect username or password.</div>'; }
  if (err === 'lock') { errorHtml = '<div class="error">Too many attempts. Wait 15 minutes.</div>'; }

  res.send('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FLIK | Sign In</title><link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:"DM Sans",sans-serif;background:#FAF7F2;display:flex;align-items:center;justify-content:center;min-height:100vh;}.card{background:#FFFEF9;border-radius:18px;padding:48px 40px 40px;width:380px;box-shadow:0 8px 40px rgba(15,15,16,0.12);border:1px solid rgba(45,106,79,0.13);}.logo{display:flex;align-items:center;gap:12px;margin-bottom:32px;}.lmark{width:42px;height:42px;border-radius:11px;background:linear-gradient(135deg,#1B4332,#40916C);display:flex;align-items:center;justify-content:center;}.lmark svg{width:22px;height:22px;fill:white;}.brand{font-family:"Playfair Display",serif;font-size:20px;font-weight:700;color:#1B4332;display:block;}.sub{font-size:10px;font-weight:600;letter-spacing:.15em;text-transform:uppercase;color:#9CA3AF;}h1{font-family:"Playfair Display",serif;font-size:22px;font-weight:700;color:#1C1C1E;margin-bottom:6px;}p.desc{font-size:13px;color:#6B7280;margin-bottom:28px;line-height:1.5;}label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px;}input{width:100%;padding:11px 14px;border:1.5px solid rgba(45,106,79,0.22);border-radius:9px;font-family:"DM Sans",sans-serif;font-size:14px;color:#1C1C1E;outline:none;background:#FAF7F2;transition:border-color .18s;margin-bottom:16px;}input:focus{border-color:#40916C;}button{width:100%;padding:12px;border:none;border-radius:10px;background:linear-gradient(135deg,#1B4332,#40916C);color:white;font-family:"DM Sans",sans-serif;font-size:15px;font-weight:600;cursor:pointer;margin-top:4px;}.error{background:#FEE2E2;border:1px solid #FECACA;border-radius:8px;padding:10px 14px;font-size:13px;color:#991B1B;margin-bottom:18px;}.footer{text-align:center;margin-top:20px;font-size:11px;color:#9CA3AF;}</style></head><body><div class="card"><div class="logo"><div class="lmark"><svg viewBox="0 0 24 24"><path d="M18.06 22.99h1.66c.84 0 1.53-.64 1.63-1.46L23 5.05h-5V1h-1.97v4.05h-4.97l.3 2.34c1.71.47 3.31 1.32 4.27 2.26 1.44 1.42 2.43 2.89 2.43 5.29v8.05zM1 21.99V21h15.03v.99c0 .55-.45 1-1.01 1H2.01c-.56 0-1.01-.45-1.01-1zm15.03-7c0-4.5-6.72-5.5-7.52-5.5-4.5 0-7.51 3.03-7.51 5.5v5h15.03v-5z"/></svg></div><div><span class="brand">FLIK</span><span class="sub">Survey Intelligence</span></div></div><h1>Welcome back</h1><p class="desc">Sign in to access the analytics dashboard.</p>' + errorHtml + '<form method="POST" action="/login"><label for="u">Username</label><input type="text" id="u" name="username" autocomplete="username" required><label for="p">Password</label><input type="password" id="p" name="password" autocomplete="current-password" required><button type="submit">Sign In</button></form><p class="footer">FLIK Hospitality Group &mdash; Internal Analytics</p></div></body></html>');
});

// Brute force protection
var loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  handler: function(req, res) {
    res.redirect('/login?error=lock');
  }
});

// Login POST
app.post('/login', loginLimiter, function(req, res) {
  var username = (req.body.username || '').trim().toLowerCase();
  var password = req.body.password || '';

  if (!username || !password) {
    return res.redirect('/login?error=bad');
  }

  var users = [];
  try {
    users = JSON.parse(process.env.APP_USERS || '[]');
  } catch (e) {
    console.error('APP_USERS parse error:', e.message);
    return res.redirect('/login?error=bad');
  }

  var user = null;
  for (var i = 0; i < users.length; i++) {
    if (users[i].username.toLowerCase() === username) {
      user = users[i];
      break;
    }
  }

  if (!user) {
    return res.redirect('/login?error=bad');
  }

  bcrypt.compare(password, user.passwordHash, function(err, match) {
    if (err || !match) {
      return res.redirect('/login?error=bad');
    }
    req.session.authenticated = true;
    req.session.user = {
      username: user.username,
      name: user.name || user.username
    };
    var returnTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    res.redirect(returnTo);
  });
});

// Logout
app.get('/logout', function(req, res) {
  req.session.destroy(function() {
    res.redirect('/login');
  });
});

// Who am I
app.get('/api/me', requireAuth, function(req, res) {
  res.json({
    username: req.session.user.username,
    name:     req.session.user.name
  });
});

// Snowflake connection
var sfConnection = null;
var sfConnecting = false;

function getSnowflakeConnection(callback) {
  if (sfConnection && sfConnection.isUp()) {
    return callback(null, sfConnection);
  }
  if (sfConnecting) {
    setTimeout(function() { getSnowflakeConnection(callback); }, 500);
    return;
  }
  sfConnecting = true;
  var conn = snowflake.createConnection({
    account:        process.env.SNOWFLAKE_ACCOUNT,
    username:       process.env.SNOWFLAKE_USERNAME,
    password:       process.env.SNOWFLAKE_PASSWORD,
    database:       'FLIK_ANALYTICS',
    schema:         'CURIOSITY',
    warehouse:      process.env.SNOWFLAKE_WAREHOUSE,
    role:           process.env.SNOWFLAKE_ROLE,
    loginTimeout:   30,
    networkTimeout: 60000
  });
  conn.connect(function(err, c) {
    sfConnecting = false;
    if (err) {
      console.error('Snowflake connection error:', err.message);
      return callback(err);
    }
    sfConnection = c;
    console.log('Snowflake connected.');
    callback(null, sfConnection);
  });
}

// Survey data endpoint
app.get('/api/survey-data', requireAuth, function(req, res) {
  var startDate = req.query.startDate;
  var endDate   = req.query.endDate;
  var sap       = req.query.sap;

  var where  = ['CATEGORY IS NOT NULL', 'SCORE IS NOT NULL', 'IS_SURVEY_COMPLETE = TRUE'];
  var params = [];

  if (startDate) {
    where.push('FISCAL_DATE >= ?');
    params.push(startDate);
  }
  if (endDate) {
    where.push('FISCAL_DATE <= ?');
    params.push(endDate);
  }
  if (sap) {
    where.push('UNIT_SAP_NUMBER = ?');
    params.push(parseInt(sap, 10));
  }

  var sql = 'SELECT SURVEY_PLATFORM, SURVEY_NAME, SURVEY_ID, RESPONSE_ID, UNIT_SAP_NUMBER, UNIT_NAME, QUESTION_TEXT, SCORE, CATEGORY FROM FLIK_ANALYTICS.CURIOSITY.SURVEYS_COMBINED WHERE ' + where.join(' AND ') + ' ORDER BY UNIT_SAP_NUMBER';

  getSnowflakeConnection(function(err, conn) {
    if (err) {
      return res.status(503).json({ error: 'Database unavailable: ' + err.message });
    }
    conn.execute({
      sqlText:  sql,
      binds:    params.length ? params : undefined,
      complete: function(queryErr, stmt, rows) {
        if (queryErr) {
          sfConnection = null;
          console.error('Snowflake query error:', queryErr.message);
          return res.status(500).json({ error: 'Query failed: ' + queryErr.message });
        }
        var out = rows.map(function(r) {
          return {
            survey_platform:         r.SURVEY_PLATFORM || '',
            survey_name:             r.SURVEY_NAME     || '',
            survey_id:               r.SURVEY_ID       || '',
            response_id:             r.RESPONSE_ID     || '',
            unit_sap_number:         r.UNIT_SAP_NUMBER || 0,
            unit:                    r.UNIT_NAME       || '',
            analytics_question_text: r.QUESTION_TEXT   || '',
            csat:                    parseFloat(r.SCORE) || 0,
            csat_reason:             r.CATEGORY        || ''
          };
        });
        console.log(out.length + ' rows served to ' + req.session.user.username);
        res.json(out);
      }
    });
  });
});

// AI proxy — Anthropic with Groq fallback
var aiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 30,
  message:  { error: 'Too many requests. Wait a few minutes.' },
  keyGenerator: function(req) {
    return req.session && req.session.user ? req.session.user.username : req.ip;
  }
});

app.post('/api/chat', requireAuth, aiLimiter, function(req, res) {
  var model      = req.body.model;
  var max_tokens = req.body.max_tokens;
  var system     = req.body.system;
  var messages   = req.body.messages;

  if (!messages || !Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: 'messages array required.' });
  }

  // Try Anthropic first
  fetch('https://api.anthropic.com/v1/messages', {
    method:  'POST',
    headers: {
      'Content-Type':      'application/json',
      'anthropic-version': '2023-06-01',
      'x-api-key':         process.env.ANTHROPIC_API_KEY
    },
    body: JSON.stringify({
      model:      model || 'claude-sonnet-4-20250514',
      max_tokens: max_tokens || 4000,
      system:     system,
      messages:   messages
    })
  })
  .then(function(aRes) {
    if (aRes.status === 429 || aRes.status === 529 || aRes.status === 503) {
      throw new Error('RATE_LIMITED');
    }
    if (!aRes.ok) {
      return aRes.text().then(function(t) {
        throw new Error('ANTHROPIC_ERROR:' + aRes.status + ':' + t.slice(0, 100));
      });
    }
    return aRes.json().then(function(data) {
      data._provider = 'anthropic';
      res.json(data);
    });
  })
  .catch(function(aErr) {
    var shouldFallback = aErr.message === 'RATE_LIMITED' ||
                         aErr.message.indexOf('ANTHROPIC_ERROR:5') === 0;

    if (!shouldFallback) {
      return res.status(502).json({ error: 'AI error: ' + aErr.message });
    }

    // Groq fallback
    var groqMessages = system
      ? [{ role: 'system', content: system }].concat(messages)
      : messages.slice();

    fetch('https://api.groq.com/openai/v1/chat/completions', {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': 'Bearer ' + process.env.GROQ_API_KEY
      },
      body: JSON.stringify({
        model:       'llama-3.1-70b-versatile',
        max_tokens:  max_tokens || 4000,
        messages:    groqMessages,
        temperature: 0.3
      })
    })
    .then(function(gRes) {
      if (!gRes.ok) {
        return gRes.text().then(function(t) {
          console.error('Groq error:', gRes.status, t.slice(0, 200));
          res.status(502).json({ error: 'Both AI services unavailable.' });
        });
      }
      return gRes.json().then(function(gData) {
        res.json({
          content:     [{ type: 'text', text: gData.choices[0].message.content }],
          stop_reason: gData.choices[0].finish_reason === 'length' ? 'max_tokens' : 'end_turn',
          _provider:   'groq',
          _fallback:   true
        });
      });
    })
    .catch(function(gErr) {
      res.status(502).json({ error: 'All AI services unavailable: ' + gErr.message });
    });
  });
});

// Serve frontend
app.get('/', requireAuth, function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check
app.get('/health', function(req, res) {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Catch all
app.use(function(req, res) {
  if (!req.session || !req.session.authenticated) {
    return res.redirect('/login');
  }
  res.status(404).send('Not found');
});

// Start
var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('FLIK Survey Intelligence on port ' + PORT + ' [' + (process.env.NODE_ENV || 'development') + ']');
});
