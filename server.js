'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// FLIK Survey Intelligence — Production Server
// AI  : Snowflake Cortex (claude-sonnet-4-6)
// Auth: bcrypt login/signup + forgot/reset password via Resend email
// DB  : Snowflake key-pair (RSA JWT) — fresh connection per request
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

// ── In-memory pending signups { email -> { fullname, hash, code, expires } } ──
const pendingSignups = new Map();

// ── Send email helper — uses Brevo (any recipient) or Resend fallback ─────────
async function sendEmail(to, subject, html) {
  const brevoKey  = process.env.BREVO_API_KEY;
  const resendKey = process.env.RESEND_API_KEY;

  if (!brevoKey && !resendKey) {
    console.log('[Email] No email key set. To: ' + to + ' | Subject: ' + subject);
    return;
  }

  if (brevoKey) {
    // Brevo — no domain verification needed, sends to any address
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'api-key': brevoKey },
      body: JSON.stringify({
        sender:      { name: 'FLIK Survey Intelligence', email: 'hard.parikh@compass-usa.com' },
        to:          [{ email: to }],
        subject:     subject,
        htmlContent: html
      })
    });
    if (!r.ok) { const t = await r.text(); throw new Error('Brevo error: ' + t.slice(0, 100)); }
  } else {
    // Resend fallback — only works for verified addresses on free plan
    const r = await fetch('https://api.resend.com/emails', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + resendKey },
      body: JSON.stringify({ from: 'FLIK Survey Intelligence <onboarding@resend.dev>', to: [to], subject, html })
    });
    if (!r.ok) { const t = await r.text(); throw new Error('Resend error: ' + t.slice(0, 100)); }
  }
}

// ── In-memory reset tokens { token -> { email, expires } } ───────────────────
const resetTokens = new Map();

// ── Auth constants ────────────────────────────────────────────────────────────
const ALLOWED_DOMAIN = (process.env.ALLOWED_DOMAIN || 'compass-usa.com').toLowerCase();

function validDomain(email) {
  return email && email.endsWith('@' + ALLOWED_DOMAIN);
}

// ── Shared auth page CSS ──────────────────────────────────────────────────────
const AUTH_CSS = `
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
.error{background:rgba(231,111,81,0.15);border:1px solid rgba(231,111,81,0.35);border-radius:9px;padding:11px 14px;font-size:13px;color:#FCA5A5;margin-bottom:16px;}
.success{background:rgba(64,145,108,0.15);border:1px solid rgba(64,145,108,0.35);border-radius:9px;padding:11px 14px;font-size:13px;color:#86EFAC;margin-bottom:16px;}
.switch{text-align:center;margin-top:20px;font-size:13px;color:rgba(216,243,220,0.4);}
.switch a,.link{color:#52B788;text-decoration:none;font-weight:600;}
.hint{font-size:11px;color:rgba(82,183,136,0.5);margin-top:5px;}
.footer{text-align:center;margin-top:20px;font-size:10px;color:rgba(216,243,220,0.15);}
.forgot{text-align:right;margin-top:8px;}
.forgot a{font-size:12px;color:rgba(82,183,136,0.6);text-decoration:none;}
.forgot a:hover{color:#52B788;}
`;

const AUTH_HEAD = (title) => `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FLIK | ${title}</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>${AUTH_CSS}</style></head><body>`;

const LOGO = `<div class="logo">
  <div class="lmark"><svg viewBox="0 0 24 24"><path d="M18.06 22.99h1.66c.84 0 1.53-.64 1.63-1.46L23 5.05h-5V1h-1.97v4.05h-4.97l.3 2.34c1.71.47 3.31 1.32 4.27 2.26 1.44 1.42 2.43 2.89 2.43 5.29v8.05zM1 21.99V21h15.03v.99c0 .55-.45 1-1.01 1H2.01c-.56 0-1.01-.45-1.01-1zm15.03-7c0-4.5-6.72-5.5-7.52-5.5-4.5 0-7.51 3.03-7.51 5.5v5h15.03v-5z"/></svg></div>
  <div><span class="brand">FLIK</span><span class="sub">Survey Intelligence</span></div>
</div>`;

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not authenticated.' });
  res.redirect('/login');
}

// ── Login ─────────────────────────────────────────────────────────────────────
app.get('/login', function (req, res) {
  if (req.session && req.session.authenticated) return res.redirect('/');
  const errMap = {
    bad:    'Incorrect email or password.',
    domain: `Only @${ALLOWED_DOMAIN} email addresses are allowed.`
  };
  const successMap = { registered: 'Account created! You can now sign in.', reset: 'Password updated! Sign in with your new password.' };
  const err = errMap[req.query.error] || '';
  const suc = successMap[req.query.msg] || '';

  res.send(AUTH_HEAD('Sign In') + `<div class="card">${LOGO}
  <h1>Welcome back</h1>
  <p class="desc">Sign in to access FLIK analytics.</p>
  ${err ? `<div class="error">${err}</div>` : ''}
  ${suc ? `<div class="success">${suc}</div>` : ''}
  <form method="POST" action="/login">
    <label>Work Email</label>
    <input type="email" name="email" placeholder="you@${ALLOWED_DOMAIN}" autocomplete="email" required autofocus>
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <div class="forgot"><a href="/forgot-password">Forgot password?</a></div>
    <button type="submit">Sign In</button>
  </form>
  <div class="switch">No account? <a href="/signup">Sign up</a></div>
  <p class="footer">FLIK Hospitality Group -- Internal Analytics</p>
</div></body></html>`);
});

app.post('/login', async function (req, res) {
  const email    = (req.body.email    || '').trim().toLowerCase();
  const password =  req.body.password || '';
  if (!email || !password)    return res.redirect('/login?error=bad');
  if (!validDomain(email))    return res.redirect('/login?error=domain');
  try {
    const user = await dbGetUser(email);
    if (!user) return res.redirect('/login?error=bad');
    const match = await bcrypt.compare(password, user.PASSWORD_HASH);
    if (!match) return res.redirect('/login?error=bad');
    req.session.authenticated = true;
    req.session.user = { email: user.EMAIL, name: user.FULL_NAME || email.split('@')[0] };
    res.redirect('/');
  } catch (e) {
    console.error('[Login]', e.message);
    res.redirect('/login?error=bad');
  }
});

// ── Signup ────────────────────────────────────────────────────────────────────
app.get('/signup', function (req, res) {
  if (req.session && req.session.authenticated) return res.redirect('/');
  const errMap = {
    domain:   `Only @${ALLOWED_DOMAIN} email addresses can register.`,
    exists:   'An account with this email already exists.',
    weak:     'Password must be at least 8 characters.',
    mismatch: 'Passwords do not match.',
    failed:   'Registration failed. Please try again.'
  };
  const err = errMap[req.query.error] || '';

  res.send(AUTH_HEAD('Sign Up') + `<div class="card">${LOGO}
  <h1>Create account</h1>
  <p class="desc">Join the FLIK analytics platform.</p>
  ${err ? `<div class="error">${err}</div>` : ''}
  <form method="POST" action="/signup">
    <label>Full Name</label>
    <input type="text" name="fullname" placeholder="Hard Parikh" autocomplete="name" required autofocus>
    <label>Work Email</label>
    <input type="email" name="email" placeholder="you@${ALLOWED_DOMAIN}" autocomplete="email" required>
    <p class="hint">Must be a @${ALLOWED_DOMAIN} address</p>
    <label>Password</label>
    <input type="password" name="password" placeholder="Min. 8 characters" autocomplete="new-password" required>
    <label>Confirm Password</label>
    <input type="password" name="confirm" placeholder="Repeat password" autocomplete="new-password" required>
    <button type="submit">Create Account</button>
  </form>
  <div class="switch">Already have an account? <a href="/login">Sign in</a></div>
  <p class="footer">FLIK Hospitality Group -- Internal Analytics</p>
</div></body></html>`);
});

app.post('/signup', async function (req, res) {
  const fullname = (req.body.fullname || '').trim();
  const email    = (req.body.email    || '').trim().toLowerCase();
  const password =  req.body.password || '';
  const confirm  =  req.body.confirm  || '';
  if (!validDomain(email))   return res.redirect('/signup?error=domain');
  if (password.length < 8)   return res.redirect('/signup?error=weak');
  if (password !== confirm)  return res.redirect('/signup?error=mismatch');
  try {
    const existing = await dbGetUser(email);
    if (existing) return res.redirect('/signup?error=exists');

    // Generate 6-digit code
    const code    = String(Math.floor(100000 + Math.random() * 900000));
    const expires = Date.now() + 10 * 60 * 1000; // 10 minutes
    const hash    = await bcrypt.hash(password, 12);

    // Store pending signup
    pendingSignups.set(email, { fullname, hash, code, expires });

    // Send verification email
    const firstName = fullname.split(' ')[0] || 'there';
    await sendEmail(email, 'Your FLIK verification code', `
      <div style="font-family:'DM Sans',sans-serif;max-width:480px;margin:0 auto;padding:40px 24px;background:#FFFEF9;border-radius:16px;">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:28px;">
          <div style="width:40px;height:40px;border-radius:10px;background:#2D6A4F;display:flex;align-items:center;justify-content:center;">
            <span style="color:white;font-size:18px;font-weight:700;">F</span>
          </div>
          <div>
            <div style="font-size:17px;font-weight:700;color:#1B4332;">FLIK Survey Intelligence</div>
            <div style="font-size:10px;color:#9CA3AF;text-transform:uppercase;letter-spacing:.1em;">Email Verification</div>
          </div>
        </div>
        <h2 style="color:#1C1C1E;font-size:22px;margin-bottom:8px;">Hi ${firstName},</h2>
        <p style="color:#6B7280;line-height:1.6;margin-bottom:24px;">
          Use the code below to verify your email and complete your FLIK account setup.
          This code expires in <strong>10 minutes</strong>.
        </p>
        <div style="background:#F0FDF4;border:2px solid #2D6A4F;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
          <div style="font-size:36px;font-weight:700;color:#1B4332;letter-spacing:8px;font-family:monospace;">${code}</div>
          <div style="font-size:12px;color:#6B7280;margin-top:8px;">Enter this code on the verification page</div>
        </div>
        <p style="color:#9CA3AF;font-size:12px;line-height:1.6;">
          If you did not request this, you can safely ignore this email.
        </p>
        <hr style="border:none;border-top:1px solid #E5E7EB;margin:24px 0;">
        <p style="color:#D1D5DB;font-size:11px;">FLIK Hospitality Group -- Internal Analytics</p>
      </div>
    `);

    // If no Resend key, log the code for development
    if (!process.env.RESEND_API_KEY) {
      console.log('[Verify] Code for ' + email + ': ' + code);
    }

    res.redirect('/verify-email?email=' + encodeURIComponent(email));
  } catch (e) {
    console.error('[Signup]', e.message);
    res.redirect('/signup?error=failed');
  }
});

// ── Verify email ──────────────────────────────────────────────────────────────
app.get('/verify-email', function (req, res) {
  if (req.session && req.session.authenticated) return res.redirect('/');
  const email = (req.query.email || '').trim().toLowerCase();
  const errMap = {
    wrong:   'Incorrect code. Please try again.',
    expired: 'Code expired. Please sign up again.',
    failed:  'Verification failed. Please try again.'
  };
  const err = errMap[req.query.error] || '';

  if (!email) return res.redirect('/signup');

  res.send(AUTH_HEAD('Verify Email') + `<div class="card">${LOGO}
  <h1>Check your email</h1>
  <p class="desc">We sent a 6-digit code to <strong style="color:#52B788;">${email}</strong>. Enter it below to verify your account.</p>
  ${err ? `<div class="error">${err}</div>` : ''}
  <form method="POST" action="/verify-email">
    <input type="hidden" name="email" value="${email}">
    <label>Verification Code</label>
    <input type="text" name="code" placeholder="000000" maxlength="6" autocomplete="one-time-code"
      required autofocus inputmode="numeric"
      style="font-size:28px;font-weight:700;letter-spacing:10px;text-align:center;font-family:monospace;">
    <button type="submit">Verify &amp; Create Account</button>
  </form>
  <div class="switch">Wrong email? <a href="/signup">Start over</a></div>
  <p style="text-align:center;margin-top:12px;font-size:12px;color:rgba(216,243,220,0.35);">Code expires in 10 minutes</p>
</div></body></html>`);
});

app.post('/verify-email', async function (req, res) {
  const email = (req.body.email || '').trim().toLowerCase();
  const code  = (req.body.code  || '').trim();

  const pending = pendingSignups.get(email);
  if (!pending || Date.now() > pending.expires) {
    pendingSignups.delete(email);
    return res.redirect('/verify-email?email=' + encodeURIComponent(email) + '&error=expired');
  }
  if (code !== pending.code) {
    return res.redirect('/verify-email?email=' + encodeURIComponent(email) + '&error=wrong');
  }

  try {
    await dbCreateUser(email, pending.fullname, pending.hash);
    pendingSignups.delete(email);
    res.redirect('/login?msg=registered');
  } catch (e) {
    console.error('[Verify]', e.message);
    if (e.message === 'EMAIL_EXISTS') return res.redirect('/signup?error=exists');
    res.redirect('/verify-email?email=' + encodeURIComponent(email) + '&error=failed');
  }
});


app.get('/forgot-password', function (req, res) {
  if (req.session && req.session.authenticated) return res.redirect('/');
  const msg = req.query.msg === 'sent'
    ? '<div class="success">If that email exists, a reset link has been sent. Check your inbox.</div>'
    : (req.query.msg === 'failed' ? '<div class="error">Could not send reset email. Please try again.</div>' : '');

  res.send(AUTH_HEAD('Forgot Password') + `<div class="card">${LOGO}
  <h1>Forgot password?</h1>
  <p class="desc">Enter your work email and we will send you a reset link.</p>
  ${msg}
  <form method="POST" action="/forgot-password">
    <label>Work Email</label>
    <input type="email" name="email" placeholder="you@${ALLOWED_DOMAIN}" required autofocus>
    <button type="submit">Send Reset Link</button>
  </form>
  <div class="switch"><a href="/login">Back to sign in</a></div>
</div></body></html>`);
});

app.post('/forgot-password', async function (req, res) {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email) return res.redirect('/forgot-password');

  try {
    const user = await dbGetUser(email);
    // Always redirect to sent -- never reveal if email exists
    if (!user) return res.redirect('/forgot-password?msg=sent');

    const token   = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 30 * 60 * 1000; // 30 minutes
    resetTokens.set(token, { email, expires });

    const resetUrl  = (process.env.APP_URL || 'http://localhost:3000') + '/reset-password?token=' + token;
    const firstName = (user.FULL_NAME || email.split('@')[0]).split(' ')[0];

    // Send email via Resend
    await sendEmail(email, 'Reset your FLIK password', `
            <div style="font-family:'DM Sans',sans-serif;max-width:480px;margin:0 auto;padding:40px 24px;background:#FFFEF9;border-radius:16px;">
              <div style="display:flex;align-items:center;gap:12px;margin-bottom:28px;">
                <div style="width:40px;height:40px;border-radius:10px;background:#2D6A4F;display:flex;align-items:center;justify-content:center;">
                  <span style="color:white;font-size:18px;font-weight:700;">F</span>
                </div>
                <div>
                  <div style="font-size:17px;font-weight:700;color:#1B4332;">FLIK Survey Intelligence</div>
                  <div style="font-size:10px;color:#9CA3AF;text-transform:uppercase;letter-spacing:.1em;">Password Reset</div>
                </div>
              </div>
              <h2 style="color:#1C1C1E;font-size:22px;margin-bottom:8px;">Hi ${firstName},</h2>
              <p style="color:#6B7280;line-height:1.6;margin-bottom:24px;">
                We received a request to reset your FLIK password. Click the button below to set a new password.
                This link expires in <strong>30 minutes</strong>.
              </p>
              <table cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
                <tr>
                  <td style="background-color:#2D6A4F;border-radius:10px;padding:14px 32px;">
                    <a href="${resetUrl}" style="color:#ffffff !important;text-decoration:none;font-weight:600;font-size:15px;display:inline-block;">Reset My Password</a>
                  </td>
                </tr>
              </table>
              <p style="color:#9CA3AF;font-size:12px;line-height:1.6;">
                If you did not request a password reset, you can safely ignore this email.<br>
                Your password will not change.
              </p>
              <hr style="border:none;border-top:1px solid #E5E7EB;margin:24px 0;">
              <p style="color:#D1D5DB;font-size:11px;">FLIK Hospitality Group -- Internal Analytics</p>
            </div>
          `);

    res.redirect('/forgot-password?msg=sent');
  } catch (e) {
    console.error('[Forgot Password]', e.message);
    res.redirect('/forgot-password?msg=failed');
  }
});

// ── Reset password ────────────────────────────────────────────────────────────
app.get('/reset-password', function (req, res) {
  const token = req.query.token || '';
  const entry = resetTokens.get(token);
  const errMap = {
    weak:     'Password must be at least 8 characters.',
    mismatch: 'Passwords do not match.',
    failed:   'Reset failed. Please try again.'
  };
  const err = errMap[req.query.error] || '';

  if (!token || !entry || Date.now() > entry.expires) {
    return res.send(AUTH_HEAD('Link Expired') + `<div class="card">${LOGO}
  <h1>Link expired</h1>
  <p class="desc">This reset link is invalid or has expired. Links are valid for 30 minutes.</p>
  <a href="/forgot-password" style="display:block;text-align:center;margin-top:24px;color:#52B788;text-decoration:none;font-weight:600;">Request a new link</a>
</div></body></html>`);
  }

  res.send(AUTH_HEAD('Reset Password') + `<div class="card">${LOGO}
  <h1>Set new password</h1>
  <p class="desc">Choose a strong new password for your account.</p>
  ${err ? `<div class="error">${err}</div>` : ''}
  <form method="POST" action="/reset-password">
    <input type="hidden" name="token" value="${token}">
    <label>New Password</label>
    <input type="password" name="password" placeholder="Min. 8 characters" autocomplete="new-password" required autofocus>
    <label>Confirm Password</label>
    <input type="password" name="confirm" placeholder="Repeat password" autocomplete="new-password" required>
    <button type="submit">Update Password</button>
  </form>
</div></body></html>`);
});

app.post('/reset-password', async function (req, res) {
  const token    = req.body.token    || '';
  const password = req.body.password || '';
  const confirm  = req.body.confirm  || '';
  const entry    = resetTokens.get(token);

  if (!entry || Date.now() > entry.expires) return res.redirect('/forgot-password');
  if (password.length < 8)  return res.redirect('/reset-password?token=' + token + '&error=weak');
  if (password !== confirm)  return res.redirect('/reset-password?token=' + token + '&error=mismatch');

  try {
    const hash = await bcrypt.hash(password, 12);
    const e    = entry.email.replace(/'/g, "''");
    await new Promise(function (resolve, reject) {
      sfQuery(
        `UPDATE FLIK_ANALYTICS.CURIOSITY_WIDGETS.APP_USERS SET PASSWORD_HASH = '${hash}' WHERE EMAIL = '${e}'`,
        function (err) { if (err) reject(err); else resolve(); }
      );
    });
    resetTokens.delete(token);
    res.redirect('/login?msg=reset');
  } catch (e) {
    console.error('[Reset Password]', e.message);
    res.redirect('/reset-password?token=' + token + '&error=failed');
  }
});

// ── Logout ────────────────────────────────────────────────────────────────────
app.get('/logout', function (req, res) {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/api/me', requireAuth, function (req, res) {
  res.json({ email: req.session.user.email, name: req.session.user.name });
});

// ── Snowflake — fresh connection per request ──────────────────────────────────
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
  try { opts = buildConnOptions(); } catch (e) { return callback(e); }
  const conn = snowflake.createConnection(opts);
  conn.connect(function (err, c) {
    if (err) { console.error('[Snowflake]', err.message); return callback(err); }
    c.execute({
      sqlText:  sql,
      complete: function (qErr, stmt, rows) {
        try { c.destroy(function () {}); } catch (e) {}
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

// ── User DB helpers ───────────────────────────────────────────────────────────
function dbGetUser(email) {
  return new Promise(function (resolve, reject) {
    const e = email.replace(/'/g, "''");
    sfQuery(
      `SELECT * FROM FLIK_ANALYTICS.CURIOSITY_WIDGETS.APP_USERS WHERE EMAIL = '${e}' LIMIT 1`,
      function (err, rows) { if (err) return reject(err); resolve(rows && rows.length ? rows[0] : null); }
    );
  });
}

function dbCreateUser(email, fullname, hash) {
  return new Promise(function (resolve, reject) {
    const e = email.replace(/'/g, "''");
    const n = fullname.replace(/'/g, "''");
    sfQuery(
      `MERGE INTO FLIK_ANALYTICS.CURIOSITY_WIDGETS.APP_USERS AS t
       USING (SELECT '${e}' AS EMAIL) AS s ON t.EMAIL = s.EMAIL
       WHEN NOT MATCHED THEN INSERT (EMAIL, FULL_NAME, PASSWORD_HASH, IS_ACTIVE)
       VALUES ('${e}', '${n}', '${hash}', TRUE)`,
      function (err, rows) {
        if (err) return reject(err);
        const inserted = rows && rows[0] ? (rows[0]['number of rows inserted'] || 0) : 0;
        if (inserted === 0) return reject(new Error('EMAIL_EXISTS'));
        resolve();
      }
    );
  });
}

// ── Survey data — two simple queries, fast and reliable ──────────────────────
app.get('/api/survey-data', requireAuth, function (req, res) {

  // Query 1: Unit-month aggregates
  const sql1 = `
    SELECT
      COALESCE(NULLIF(UNIT_SAP_NUMBER::VARCHAR, '0'), UNIT) AS UNIT_KEY,
      UNIT                                                   AS UNIT_NAME,
      UNIT_SAP_NUMBER::VARCHAR                              AS UNIT_SAP,
      TO_CHAR(AUDIT_DATE, 'YYYY-MM')                        AS MONTH,
      COUNT(DISTINCT RESPONSE_ID)                           AS RESPONSES,
      AVG(CSAT)                                             AS AVG_CSAT,
      SUM(CASE WHEN CSAT < 3  THEN 1 ELSE 0 END)           AS NEG_COUNT,
      SUM(CASE WHEN CSAT >= 4 THEN 1 ELSE 0 END)           AS POS_COUNT,
      SUM(CASE WHEN CSAT <= 2 THEN 1 ELSE 0 END)           AS DET_COUNT,
      COUNT(CSAT)                                           AS SCORE_COUNT
    FROM FLIK_ANALYTICS.CURIOSITY_WIDGETS.RESPONSES
    WHERE CSAT IS NOT NULL
      AND CSAT_REASON IS NOT NULL
      AND AUDIT_DATE IS NOT NULL
    GROUP BY 1, 2, 3, 4
    ORDER BY 1, 4
  `;

  // Query 2: Top issues per unit — total count across all time
  const sql2 = `
    SELECT
      COALESCE(NULLIF(UNIT_SAP_NUMBER::VARCHAR, '0'), UNIT) AS UNIT_KEY,
      CSAT_REASON,
      COUNT(DISTINCT RESPONSE_ID) AS CNT
    FROM FLIK_ANALYTICS.CURIOSITY_WIDGETS.RESPONSES
    WHERE CSAT_REASON IS NOT NULL
      AND TRIM(CSAT_REASON) != ''
      AND RESPONSE_ID IS NOT NULL
    GROUP BY 1, 2
    ORDER BY 1, 3 DESC
  `;

  sfQuery(sql1, function (err1, rows1) {
    if (err1) {
      console.error('[Survey Data] Query 1 error:', err1.message);
      return res.status(500).json({ error: err1.message });
    }

    sfQuery(sql2, function (err2, rows2) {
      if (err2) {
        console.error('[Survey Data] Query 2 error:', err2.message);
        // Return data without issues rather than failing
        rows2 = [];
      }

      // Build issues map: unit_key -> "reason:cnt|reason:cnt"
      var issueMap = {};
      if (rows2) {
        rows2.forEach(function (r) {
          var k = String(r.UNIT_KEY || '');
          var reason = String(r.CSAT_REASON || '').trim();
          var cnt    = parseInt(r.CNT) || 0;
          if (!k || !reason) return;
          if (!issueMap[k]) issueMap[k] = [];
          if (issueMap[k].length < 8) {
            issueMap[k].push(reason + ':' + cnt);
          }
        });
      }

      const out = rows1.map(function (r) {
        var key = String(r.UNIT_KEY || '');
        return {
          unit_key:    key,
          unit_name:   String(r.UNIT_NAME  || ''),
          unit_sap:    String(r.UNIT_SAP   || ''),
          month:       String(r.MONTH      || ''),
          responses:   parseInt(r.RESPONSES)   || 0,
          avg_csat:    parseFloat(r.AVG_CSAT)  || 0,
          neg_count:   parseInt(r.NEG_COUNT)   || 0,
          pos_count:   parseInt(r.POS_COUNT)   || 0,
          det_count:   parseInt(r.DET_COUNT)   || 0,
          score_count: parseInt(r.SCORE_COUNT) || 0,
          top_issues:  (issueMap[key] || []).join('|')
        };
      });

      console.log('[Survey Data] ' + out.length + ' unit-month rows, ' + Object.keys(issueMap).length + ' units with issues -> ' + req.session.user.email);
      res.json(out);
    });
  });
});

// ── RAG — Search relevant units via Cortex Search REST API ───────────────────
function searchUnits(query, limit, callback) {
  // Cortex Search REST API endpoint
  const account  = (process.env.SNOWFLAKE_ACCOUNT || 'uya38094.us-east-1.snowflakecomputing.com')
    .replace('.snowflakecomputing.com', '');
  const url = 'https://' + account + '.snowflakecomputing.com/api/v2/cortex/search-services/' +
    'FLIK_ANALYTICS.CURIOSITY_WIDGETS.UNIT_SEARCH:query';

  // Build JWT token for auth
  let token;
  try {
    const pk = crypto.createPrivateKey({ key: process.env.SNOWFLAKE_PRIVATE_KEY, format: 'pem' });
    const now = Math.floor(Date.now() / 1000);
    const header  = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: account.toUpperCase() + '.' + (process.env.SNOWFLAKE_USERNAME || 'PARIKH01_SRV').toUpperCase() + '.SHA256:' +
        crypto.createPublicKey(pk).export({ type: 'spki', format: 'der' }).toString('base64'),
      sub: account.toUpperCase() + '.' + (process.env.SNOWFLAKE_USERNAME || 'PARIKH01_SRV').toUpperCase(),
      iat: now,
      exp: now + 3600
    })).toString('base64url');
    const sig = crypto.sign('SHA256', Buffer.from(header + '.' + payload), { key: pk, padding: crypto.constants.RSA_PKCS1_PADDING });
    token = header + '.' + payload + '.' + sig.toString('base64url');
  } catch (e) {
    console.error('[RAG] JWT error:', e.message);
    return callback(null, []); // Fall back gracefully
  }

  fetch(url, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': 'Bearer ' + token,
      'X-Snowflake-Authorization-Token-Type': 'KEYPAIR_JWT'
    },
    body: JSON.stringify({
      query:       query,
      columns:     ['UNIT_KEY', 'UNIT_NAME', 'UNIT_SAP', 'WEIGHTED_SCORE', 'RAW_AVG',
                    'RESPONSES', 'NEG_RATE', 'CONFIDENCE', 'TOP_ISSUES', 'PERFORMANCE_TIER', 'SEARCH_TEXT'],
      limit:       limit || 15
    })
  }).then(function (r) {
    return r.json().then(function (d) {
      if (!r.ok) {
        console.warn('[RAG] Search failed:', JSON.stringify(d).slice(0, 100));
        return callback(null, []); // Fall back gracefully
      }
      callback(null, d.results || []);
    });
  }).catch(function (e) {
    console.warn('[RAG] Fetch error:', e.message);
    callback(null, []); // Fall back gracefully
  });
}

// ── Populate UNIT_ANALYTICS from computed stats ───────────────────────────────
app.post('/api/refresh-analytics', requireAuth, function (req, res) {
  const { unitStats, portfolioStats } = req.body;
  if (!unitStats || !Array.isArray(unitStats) || !unitStats.length) {
    return res.status(400).json({ error: 'unitStats required.' });
  }

  console.log('[RAG] Refreshing analytics for ' + unitStats.length + ' units...');

  // Build MERGE SQL to upsert all unit analytics
  const values = unitStats.map(function (u) {
    const key    = (u.key        || '').replace(/'/g, "''").slice(0, 254);
    const name   = (u.name       || '').replace(/'/g, "''").slice(0, 499);
    const sap    = (u.sap        || '').replace(/'/g, "''").slice(0, 99);
    const issues = (u.topReasons || []).slice(0, 10)
      .map(function (r) { return r[0] + '(' + r[1] + ')'; }).join(', ');
    const tier   = u.wScore >= 4 ? 'Thriving' : u.wScore >= 3 ? 'Neutral' : 'At-Risk';

    // Rich search text — this is what Cortex Search indexes
    const searchText = [
      'Unit: ' + name,
      'SAP: ' + sap,
      'Performance: ' + tier,
      'Weighted CSAT score: ' + u.wScore + ' out of 5',
      'Raw average: ' + u.rawAvg,
      'Response count: ' + u.responses,
      'Confidence: ' + u.conf.label,
      'Negative rate: ' + u.negRate + '%',
      'NPS: ' + u.nps,
      'Top issues: ' + issues
    ].join('. ');

    return "('" + key + "','" + name + "','" + sap + "'," +
      u.responses + ',' + u.rawAvg + ',' + u.wScore + ',' +
      u.negRate + ',' + u.posRate + ',' + u.nps + ",'" +
      u.conf.label + "','" + issues.replace(/'/g, "''") + "','" +
      tier + "','" + searchText.replace(/'/g, "''") + "',CURRENT_TIMESTAMP())";
  }).join(',\n');

  const sql = `
    CREATE TABLE IF NOT EXISTS FLIK_ANALYTICS.CURIOSITY_WIDGETS.UNIT_ANALYTICS (
      UNIT_KEY         VARCHAR(255) PRIMARY KEY,
      UNIT_NAME        VARCHAR(500),
      UNIT_SAP         VARCHAR(100),
      RESPONSES        NUMBER,
      RAW_AVG          FLOAT,
      WEIGHTED_SCORE   FLOAT,
      NEG_RATE         FLOAT,
      POS_RATE         FLOAT,
      NPS              NUMBER,
      CONFIDENCE       VARCHAR(50),
      TOP_ISSUES       VARCHAR(2000),
      PERFORMANCE_TIER VARCHAR(50),
      SEARCH_TEXT      VARCHAR(5000),
      LAST_UPDATED     TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
    )
  `;

  sfQuery(sql, function (err) {
    if (err) { console.error('[RAG] Create table error:', err.message); return res.status(500).json({ error: err.message }); }

    const mergeSql = `
      MERGE INTO FLIK_ANALYTICS.CURIOSITY_WIDGETS.UNIT_ANALYTICS AS t
      USING (SELECT * FROM VALUES ${values}
        AS v(UNIT_KEY, UNIT_NAME, UNIT_SAP, RESPONSES, RAW_AVG, WEIGHTED_SCORE,
             NEG_RATE, POS_RATE, NPS, CONFIDENCE, TOP_ISSUES, PERFORMANCE_TIER, SEARCH_TEXT, LAST_UPDATED)
      ) AS s ON t.UNIT_KEY = s.UNIT_KEY
      WHEN MATCHED THEN UPDATE SET
        UNIT_NAME = s.UNIT_NAME, UNIT_SAP = s.UNIT_SAP, RESPONSES = s.RESPONSES,
        RAW_AVG = s.RAW_AVG, WEIGHTED_SCORE = s.WEIGHTED_SCORE, NEG_RATE = s.NEG_RATE,
        POS_RATE = s.POS_RATE, NPS = s.NPS, CONFIDENCE = s.CONFIDENCE,
        TOP_ISSUES = s.TOP_ISSUES, PERFORMANCE_TIER = s.PERFORMANCE_TIER,
        SEARCH_TEXT = s.SEARCH_TEXT, LAST_UPDATED = s.LAST_UPDATED
      WHEN NOT MATCHED THEN INSERT
        (UNIT_KEY, UNIT_NAME, UNIT_SAP, RESPONSES, RAW_AVG, WEIGHTED_SCORE,
         NEG_RATE, POS_RATE, NPS, CONFIDENCE, TOP_ISSUES, PERFORMANCE_TIER, SEARCH_TEXT, LAST_UPDATED)
      VALUES
        (s.UNIT_KEY, s.UNIT_NAME, s.UNIT_SAP, s.RESPONSES, s.RAW_AVG, s.WEIGHTED_SCORE,
         s.NEG_RATE, s.POS_RATE, s.NPS, s.CONFIDENCE, s.TOP_ISSUES, s.PERFORMANCE_TIER,
         s.SEARCH_TEXT, s.LAST_UPDATED)
    `;

    sfQuery(mergeSql, function (mergeErr) {
      if (mergeErr) { console.error('[RAG] Merge error:', mergeErr.message); return res.status(500).json({ error: mergeErr.message }); }
      console.log('[RAG] Analytics refreshed for ' + unitStats.length + ' units.');
      res.json({ ok: true, units: unitStats.length });
    });
  });
});

// ── AI — Snowflake Cortex with RAG ────────────────────────────────────────────
app.post('/api/chat', requireAuth, function (req, res) {
  const { system, messages, userQuery, portfolioStats, useRag } = req.body;
  if (!messages || !Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: 'messages array required.' });
  }

  function buildAndCallCortex(ragUnits) {
    // Merge RAG results into system prompt if available
    let systemFinal = (system || '').slice(0, 4000);

    if (ragUnits && ragUnits.length > 0) {
      const ragSection = '\n\n## RETRIEVED UNITS (most relevant to this question)\n' +
        ragUnits.map(function (u) {
          return (u.PERFORMANCE_TIER === 'At-Risk' ? '[AT-RISK]' : '') +
            u.UNIT_NAME + '|' + u.UNIT_SAP + '|n:' + u.RESPONSES +
            '|wtd:' + u.WEIGHTED_SCORE + '|neg:' + u.NEG_RATE + '%|' +
            u.CONFIDENCE + '|' + u.TOP_ISSUES;
        }).join('\n');
      systemFinal = systemFinal + ragSection;
    }

    const recentMsgs = messages.slice(-3);
    let conversation = systemFinal + '\n\n';
    recentMsgs.forEach(function (m) {
      conversation += m.role.toUpperCase() + ': ' + (m.content || '').slice(0, 1000) + '\n\n';
    });
    conversation += 'ASSISTANT:';

    const escaped = conversation.replace(/\\/g, '\\\\').replace(/'/g, "''");
    const sql     = "SELECT SNOWFLAKE.CORTEX.COMPLETE('claude-sonnet-4-6', '" + escaped + "') AS RESPONSE";

    sfQuery(sql, function (queryErr, rows) {
      if (queryErr) {
        console.error('[Cortex]', queryErr.message);
        return res.status(500).json({ error: 'Cortex failed: ' + queryErr.message });
      }
      const text = rows && rows[0] ? String(rows[0].RESPONSE || '') : '';
      res.json({
        content:     [{ type: 'text', text: text }],
        stop_reason: 'end_turn',
        _provider:   'snowflake-cortex',
        _ragUnits:   ragUnits ? ragUnits.length : 0
      });
    });
  }

  // Use RAG if enabled and query provided
  if (useRag && userQuery) {
    searchUnits(userQuery, 15, function (err, ragUnits) {
      if (err || !ragUnits || !ragUnits.length) {
        console.log('[RAG] No results or error, falling back to standard prompt');
        buildAndCallCortex([]);
      } else {
        console.log('[RAG] Retrieved ' + ragUnits.length + ' relevant units for: ' + userQuery.slice(0, 50));
        buildAndCallCortex(ragUnits);
      }
    });
  } else {
    buildAndCallCortex([]);
  }
});

// ── Static + frontend ─────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', requireAuth, function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', function (req, res) {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use(function (req, res) {
  if (!req.session || !req.session.authenticated) return res.redirect('/login');
  res.status(404).send('Not found');
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log('FLIK Survey Intelligence on port ' + PORT + ' [' + (process.env.NODE_ENV || 'development') + ']');
  sfQuery('SELECT 1', function (err) {
    if (err) { console.error('[Startup] Snowflake failed:', err.message); return; }
    console.log('[Startup] Snowflake OK.');
    bootstrapUserTable();
  });
});