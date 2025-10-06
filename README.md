# GitHub OAuth Redirect Service

A lightweight, standalone service that acts as a universal GitHub OAuth redirect handler. This service allows you to configure **one** GitHub OAuth callback URL that works across all your environments (local, staging, production).

## How It Works

### Option 1: Simple Integration (Recommended)

1. **User initiates OAuth flow** from your app (any environment)
   - Your frontend calls your backend endpoint
   - Your backend (with OAUTH_SERVICE_TOKEN) calls `POST /github/authorize-url`
   - Service validates the token and returns the complete GitHub authorization URL
   - Your backend returns this URL to your frontend
   - Your frontend redirects: `window.location.href = authorize_url`
2. **GitHub redirects to this service** after user authorization
   - Service receives the `code` and signed `state` from GitHub
3. **Service validates and exchanges**
   - Verifies the HMAC signature of the state parameter (signed with OAUTH_SERVICE_TOKEN)
   - Ensures the state hasn't expired (10 minute limit)
   - Exchanges code for access token with GitHub
4. **Service redirects back to original environment**
   - Redirects to the validated return URL from the state
   - Includes the `github_token` as a query parameter

### Option 2: Manual Integration (Legacy)

1. Your backend calls `POST /create-state` to get just the signed state
2. Your frontend manually builds the GitHub authorization URL
3. Requires exposing `GITHUB_CLIENT_ID` to your main app (3 env vars instead of 2)

## Environment Variables

### Required

- `GITHUB_CLIENT_ID` - Your GitHub OAuth application client ID
- `GITHUB_CLIENT_SECRET` - Your GitHub OAuth application client secret
- `OAUTH_SERVICE_TOKEN` - Single authentication token (used for both authentication AND state signing)

### Optional

- `APP_REDIRECT_FALLBACK` - Fallback redirect URL if `state` is missing (default: `http://localhost:3000`)
- `PORT` - Port to run the service on (default: `3000`)

### Generating Token

Generate a secure random token:

```bash
# Generate a token
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Example Configuration

```bash
GITHUB_CLIENT_ID=Iv1.abc123
GITHUB_CLIENT_SECRET=your_secret_here

# Single authentication token (used for both auth and state signing)
OAUTH_SERVICE_TOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

### Token Management Best Practices

1. **Secure storage**: Store the token as an environment variable, never commit it to version control
2. **Rotation**: Regularly rotate the token, especially if compromised
3. **Same token for all apps**: Use the same `OAUTH_SERVICE_TOKEN` value in both the OAuth redirect service and all your apps that use it

## Local Development

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file (copy from `.env.example`):
```bash
cp .env.example .env
```

3. Edit `.env` and add your GitHub OAuth credentials

4. Run the development server:
```bash
npm run dev
```

The service will be available at `http://localhost:3000`

## Deployment

This service is designed to be deployed independently to any hosting platform. Here are guides for popular platforms:

### Vercel

1. Install Vercel CLI: `npm i -g vercel`
2. Run `vercel` in the `oauth-redirect` directory
3. Set environment variables in Vercel dashboard
4. GitHub callback URL: `https://your-service.vercel.app/github/callback`

### Render

1. Create a new **Web Service** on Render
2. Connect your repository
3. Set **Root Directory** to `oauth-redirect`
4. Set **Build Command** to `npm install`
5. Set **Start Command** to `npm start`
6. Add environment variables in Render dashboard
7. GitHub callback URL: `https://your-service.onrender.com/github/callback`

### Netlify

1. Create `netlify.toml` in the `oauth-redirect` folder:
```toml
[build]
  command = "npm install"
  publish = "."
  functions = "netlify/functions"

[[redirects]]
  from = "/*"
  to = "/.netlify/functions/server/:splat"
  status = 200
```

2. Convert to serverless function (or use Netlify Functions)
3. Deploy via Netlify CLI or GitHub integration
4. Add environment variables in Netlify dashboard

### Railway

1. Create a new project on Railway
2. Connect your repository
3. Set **Root Directory** to `oauth-redirect`
4. Add environment variables
5. Railway will auto-detect Node.js and deploy
6. GitHub callback URL: `https://your-service.up.railway.app/github/callback`

### Cloudflare Pages

1. Use Cloudflare Workers or Pages Functions
2. Adapt the Express code to Workers format
3. Deploy via Wrangler CLI
4. Add environment variables as secrets

## GitHub OAuth Application Setup

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Create a new OAuth App (or edit existing)
3. Set **Authorization callback URL** to:
   ```
   https://your-deployed-service.com/github/callback
   ```
4. Note your **Client ID** and **Client Secret**

## Endpoints

### `POST /github/authorize-url` (Recommended)

Returns the complete GitHub authorization URL. This is the simplest integration method.

**Authentication:**
- Requires `Authorization: Bearer <token>` header
- Token must match `OAUTH_SERVICE_TOKEN`

**Request Body:**
```json
{
  "return_url": "https://your-app.com",
  "scope": "user:email repo"
}
```

**Response:**
```json
{
  "authorize_url": "https://github.com/login/oauth/authorize?client_id=...&redirect_uri=...&state=...&scope=...",
  "state": "base64url_encoded_signed_state"
}
```

**Usage:**
Your backend calls this endpoint, then returns the `authorize_url` to your frontend. The frontend simply redirects: `window.location.href = authorize_url`

**Security:**
- Main app only needs 2 environment variables: `OAUTH_REDIRECT_BASE` and `OAUTH_SERVICE_TOKEN`
- No need to expose `GITHUB_CLIENT_ID` to your main app

### `GET /github/callback`

Handles GitHub OAuth callbacks.

**Query Parameters:**
- `code` (required) - Authorization code from GitHub
- `state` (required) - Cryptographically signed state parameter containing the return URL

**Response:**
- Validates the signed state parameter
- Ensures state hasn't expired
- Exchanges code for access token
- Redirects to validated URL with `github_token` query parameter

**Security:**
- State must be HMAC-signed with `OAUTH_SERVICE_TOKEN`
- State expires after 10 minutes
- Protects against open redirect and token exfiltration attacks

### `POST /create-state` (Legacy)

Creates a cryptographically signed state parameter for initiating OAuth flows. Use `/github/authorize-url` instead for simplified integration.

**Authentication:**
- Requires `Authorization: Bearer <token>` header
- Token must match `OAUTH_SERVICE_TOKEN`

**Request Body:**
```json
{
  "return_url": "https://your-app.com"
}
```

**Response:**
```json
{
  "state": "base64url_encoded_signed_state"
}
```

**Security:**
- Validates authentication token before creating state
- Returns 401 if token is invalid or missing
- ⚠️ **IMPORTANT**: Never expose tokens to the frontend - this endpoint must be called from your backend only

### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "oauth-redirect-service",
  "tokensConfigured": 3,
  "stateSecretConfigured": true
}
```

### `GET /`

Service information page showing configuration status and security features.

## Security Features

### Token-Based Authentication
Only applications with a valid authentication token can create signed states and initiate OAuth flows. This provides:
- No domain configuration needed
- Works on any hosting platform
- Per-environment access control
- Easy token revocation

### Single-Token Architecture
This service uses `OAUTH_SERVICE_TOKEN` for both:
1. **Authentication**: Validates requests from your backend
2. **State Signing**: HMAC-SHA256 signing of state parameters

Benefits:
- Simplified configuration (only 2 env vars needed in main app)
- Single token to manage and rotate
- No separate state secret to synchronize

### HMAC-Signed State Parameter
The service uses HMAC-SHA256 to cryptographically sign state parameters using `OAUTH_SERVICE_TOKEN`, preventing attackers from forging redirect URLs. Each state includes:
- The return URL
- A timestamp (expires after 10 minutes)
- A cryptographic signature

### CSRF Protection
The signed state parameter provides strong CSRF protection, ensuring that OAuth callbacks can only complete if initiated from your service with a valid token.

### Additional Security Considerations

- Always use HTTPS in production
- Keep your `GITHUB_CLIENT_SECRET` and `OAUTH_SERVICE_TOKEN` secure and private
- Set `OAUTH_SERVICE_TOKEN` to a strong random value (minimum 32 characters)
- Regularly rotate `OAUTH_SERVICE_TOKEN` if compromised (update in both services)
- Access tokens are passed as query parameters - consider implementing secure session-based handoff for production

## Integration with Your Main App

**⚠️ Critical Security Requirements:**

1. **NEVER expose OAUTH_SERVICE_TOKEN to the frontend** - tokens must stay server-side only
2. **Create a backend endpoint** that calls the OAuth redirect service on behalf of your frontend
3. **Frontend calls your backend** to get signed states, never the OAuth service directly

### Architecture

```
Frontend → Your Backend → OAuth Redirect Service
           (token here)   (validates token, creates state)
```

See `INTEGRATION.md` for complete integration examples with security best practices.

## License

MIT
