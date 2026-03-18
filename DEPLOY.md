# FLIK Survey Intelligence — Production Deployment Guide

## Files in this package
```
flik-production/
├── server.js          ← Express backend (Azure AD + Snowflake + AI proxy)
├── package.json       ← Node dependencies
├── Dockerfile         ← Container definition
├── docker-compose.yml ← Local/server deployment
├── .env.template      ← Copy this to .env and fill in values
├── .gitignore
└── public/
    └── index.html     ← The frontend app (no API keys inside)
```

---

## STEP 1 — Azure AD App Registration (15 minutes)

1. Go to portal.azure.com → Azure Active Directory → App registrations → New registration
2. Name: "FLIK Survey Intelligence"
3. Supported account types: "Accounts in this organizational directory only"
4. Redirect URI: Web → https://YOUR_DOMAIN.com/auth/callback
   - For local testing add: http://localhost:3000/auth/callback
5. Click Register

6. Copy these values into your .env:
   - Application (client) ID → AZURE_CLIENT_ID
   - Directory (tenant) ID  → AZURE_TENANT_ID

7. Go to Certificates & secrets → New client secret
   - Description: "FLIK App Secret"
   - Expires: 24 months
   - Copy the VALUE (not the ID) → AZURE_CLIENT_SECRET
   ⚠️  You can only see this value once. Copy it immediately.

8. Go to API permissions → Add permission → Microsoft Graph → Delegated
   - Add: openid, profile, email, User.Read
   - Click "Grant admin consent"

---

## STEP 2 — Groq API Key (5 minutes, free)

1. Go to console.groq.com
2. Sign up with any email (free, no credit card)
3. API Keys → Create API Key → Copy it → GROQ_API_KEY in .env

---

## STEP 3 — MongoDB Atlas (10 minutes, free tier)

Used for session storage so users stay logged in across server restarts.

1. Go to cloud.mongodb.com
2. Create free account → Build a Database → Free (M0) tier
3. Create a database user (username + password)
4. Network Access → Add IP Address → Allow access from anywhere (0.0.0.0/0)
   (or add your server's specific IP)
5. Connect → Drivers → Copy the connection string
6. Replace <password> with your database user's password
7. Paste into .env as MONGODB_URI

---

## STEP 4 — Fill in .env

```bash
cp .env.template .env
# Edit .env with your values — every REPLACE_WITH_... line must be filled
```

Generate SESSION_SECRET:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

## STEP 5 — Install and Test Locally

```bash
npm install

# Test that it starts:
NODE_ENV=development node server.js

# Open http://localhost:3000
# Should redirect to Microsoft login
# Sign in with your @yourcompany.com account
# Should redirect back and show the FLIK app loading Snowflake data
```

---

## STEP 6A — Deploy to Railway (Easiest, $5/month)

1. Push your code to a GitHub repository:
   ```bash
   git init
   git add .
   git commit -m "Initial FLIK production app"
   git remote add origin https://github.com/YOUR_ORG/flik-survey-intelligence
   git push -u origin main
   ```
   ⚠️  Make sure .gitignore is working — .env must NOT be in Git.

2. Go to railway.app → New Project → Deploy from GitHub repo
3. Select your repository
4. Go to Variables tab → Add all variables from your .env file (one by one)
5. Settings → Generate Domain → Copy the domain (e.g. flik-app.railway.app)
6. Update AZURE_REDIRECT_URL in Railway variables to: https://flik-app.railway.app/auth/callback
7. Update the redirect URI in your Azure App Registration too (Step 1 → Authentication)
8. Redeploy

---

## STEP 6B — Deploy to Azure App Service (If your company uses Azure)

```bash
# Install Azure CLI
az login
az group create --name flik-rg --location eastus
az appservice plan create --name flik-plan --resource-group flik-rg --sku B1 --is-linux
az webapp create --resource-group flik-rg --plan flik-plan --name flik-survey --runtime "NODE:20-lts"

# Set all environment variables
az webapp config appsettings set --resource-group flik-rg --name flik-survey --settings \
  NODE_ENV=production \
  SESSION_SECRET="YOUR_VALUE" \
  AZURE_CLIENT_ID="YOUR_VALUE" \
  AZURE_CLIENT_SECRET="YOUR_VALUE" \
  AZURE_TENANT_ID="YOUR_VALUE" \
  AZURE_REDIRECT_URL="https://flik-survey.azurewebsites.net/auth/callback" \
  ALLOWED_EMAIL_DOMAIN="yourcompany.com" \
  ANTHROPIC_API_KEY="YOUR_VALUE" \
  GROQ_API_KEY="YOUR_VALUE" \
  SNOWFLAKE_ACCOUNT="YOUR_VALUE" \
  SNOWFLAKE_USERNAME="YOUR_VALUE" \
  SNOWFLAKE_PASSWORD="YOUR_VALUE" \
  SNOWFLAKE_DATABASE="FLIK_ANALYTICS" \
  SNOWFLAKE_SCHEMA="CURIOSITY_WIDGETS" \
  SNOWFLAKE_WAREHOUSE="YOUR_VALUE" \
  SNOWFLAKE_ROLE="YOUR_VALUE" \
  MONGODB_URI="YOUR_VALUE"

# Deploy
az webapp deploy --resource-group flik-rg --name flik-survey --src-path .
```

Update AZURE_REDIRECT_URL to: https://flik-survey.azurewebsites.net/auth/callback
Add this URL to your Azure App Registration redirect URIs.

---

## STEP 6C — Deploy with Docker on your own server

```bash
# On your server:
git clone https://github.com/YOUR_ORG/flik-survey-intelligence
cd flik-survey-intelligence
cp .env.template .env
# Fill in .env values
docker-compose up -d

# View logs:
docker-compose logs -f

# Update app:
git pull && docker-compose up -d --build
```

---

## Using Claude Code for ongoing development

Once this is deployed, use Claude Code for all future changes:

```bash
# Install Claude Code
npm install -g @anthropic-ai/claude-code

# In your project directory:
claude

# Example prompts:
# "Add a /api/survey-data endpoint filter for survey_name"
# "The Snowflake connection is timing out — add retry logic with exponential backoff"
# "Add a /api/export endpoint that returns the current analytics as a CSV download"
# "The date filter in the header isn't triggering loadLiveData — debug it"
```

Claude Code reads your entire codebase before responding,
so it understands the full context and edits the right files directly.

---

## What each piece does at runtime

```
User opens browser
  → hits /  → server checks Azure AD session
  → not logged in → redirect to /auth/login
  → Azure AD login page
  → user signs in with @yourcompany.com account
  → Azure redirects to /auth/callback with auth code
  → server exchanges code for profile
  → checks email domain matches ALLOWED_EMAIL_DOMAIN
  → creates session → stores in MongoDB
  → redirects to /

Page loads
  → fetches /api/me → gets name, shown in header
  → fetches /api/survey-data → Snowflake query
  → DATA filled with real rows → sidebar updates

User asks question
  → POST /api/chat (session cookie authenticates)
  → server tries Anthropic API
  → if 429/503 → falls back to Groq API
  → response returned to browser
  → browser renders text + pre-built charts
```

---

## Security checklist before going live

- [ ] .env is NOT in Git (check: git status should not show .env)
- [ ] AZURE_REDIRECT_URL uses https:// not http://
- [ ] ALLOWED_EMAIL_DOMAIN is set to your company domain
- [ ] SESSION_SECRET is a random 64-char hex string (not a word)
- [ ] NODE_ENV=production (enables secure cookies)
- [ ] MongoDB Atlas IP whitelist is configured
- [ ] Snowflake role has READ-ONLY access (not SYSADMIN)
- [ ] Rate limit is set (RATE_LIMIT_MAX_REQUESTS=30)
