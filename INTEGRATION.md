# Integrating with Your Main Application

This guide shows how to integrate the OAuth redirect service with your main application.

## Overview

The OAuth redirect service acts as a central handler for GitHub OAuth callbacks across all your environments. Your main app needs to know:

1. Where to send users to start the OAuth flow (GitHub)
2. Where GitHub should redirect users after authorization (this service)
3. Where to read the returned access token

## Environment Variables in Your Main App

Add these environment variables to your main application:

```bash
# The base URL of your OAuth redirect service
OAUTH_REDIRECT_BASE=https://auth.myapp.com

# Authentication token for this environment
OAUTH_SERVICE_TOKEN=your_unique_token_for_this_environment

# Your GitHub OAuth credentials (same as the redirect service)
GITHUB_CLIENT_ID=your_github_client_id
```

## Setting Up Tokens

### 1. Generate Tokens for Each Environment

Generate a unique token for each environment:

```bash
# Production token
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Example output: a1b2c3d4e5f6789...

# Staging token
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Example output: f6e5d4c3b2a1098...

# Development token
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Example output: 9876543210abcd...
```

### 2. Configure the OAuth Redirect Service

Add all tokens to the OAuth redirect service:

```bash
# In your OAuth redirect service .env
GITHUB_CLIENT_ID=Iv1.abc123
GITHUB_CLIENT_SECRET=your_secret_here
STATE_SECRET=your_random_32_char_minimum_secret
VALID_TOKENS=a1b2c3d4e5f6789...,f6e5d4c3b2a1098...,9876543210abcd...
```

### 3. Configure Each App Environment

Each environment gets its own token:

**Production App:**
```bash
OAUTH_REDIRECT_BASE=https://auth.myapp.com
OAUTH_SERVICE_TOKEN=a1b2c3d4e5f6789...
GITHUB_CLIENT_ID=Iv1.abc123
```

**Staging App:**
```bash
OAUTH_REDIRECT_BASE=https://auth.myapp.com
OAUTH_SERVICE_TOKEN=f6e5d4c3b2a1098...
GITHUB_CLIENT_ID=Iv1.abc123
```

**Development App:**
```bash
OAUTH_REDIRECT_BASE=https://auth.myapp.com
OAUTH_SERVICE_TOKEN=9876543210abcd...
GITHUB_CLIENT_ID=Iv1.abc123
```

### Benefits of Token-Based Auth

✅ **Works on any platform**: No domain configuration needed  
✅ **No wildcard risks**: Each token is independent  
✅ **Easy revocation**: Remove token from `VALID_TOKENS` to revoke access  
✅ **Per-environment control**: Each deployment has its own token  
✅ **Simple deployment**: Just add your token to environment variables

## Auto-Detection of Current App URL

The main app automatically detects its public URL based on the hosting platform:

- **Vercel**: Uses `VERCEL_URL`
- **Netlify**: Uses `URL`
- **Render**: Uses `RENDER_EXTERNAL_URL`
- **Railway**: Uses `RAILWAY_PUBLIC_DOMAIN`
- **Cloudflare Pages**: Uses `CF_PAGES_URL`
- **Replit**: Uses `REPLIT_DEV_DOMAIN`
- **Local**: Defaults to `http://localhost:3000`

No manual configuration needed!

## Frontend Integration Example

### 1. Get OAuth Configuration

```typescript
// Fetch OAuth config from your backend
const response = await fetch('/api/auth/oauth-config');
const config = await response.json();

// Returns:
// {
//   currentAppUrl: "https://your-app.vercel.app",
//   oauthRedirectBase: "https://auth.myapp.com",
//   githubOAuthRedirectUrl: "https://auth.myapp.com/github/callback",
//   githubClientId: "your_github_client_id"
// }
```

### 2. Initiate OAuth Flow

```typescript
async function startGitHubLogin() {
  // ⚠️ IMPORTANT: Call your backend endpoint to create state
  // NEVER expose OAUTH_SERVICE_TOKEN to the frontend!
  
  // Your backend handles the token and calls the OAuth redirect service
  const stateResponse = await fetch('/api/auth/create-github-state', {
    method: 'POST'
  });
  
  if (!stateResponse.ok) {
    console.error('Failed to create state parameter');
    return;
  }
  
  const { state } = await stateResponse.json();
  
  // Build the GitHub authorization URL with the signed state
  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', config.githubClientId);
  authUrl.searchParams.set('redirect_uri', config.githubOAuthRedirectUrl);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('scope', 'user:email repo');
  
  // Redirect user to GitHub
  window.location.href = authUrl.toString();
}
```

### Backend Implementation (Required)

Your backend must provide an endpoint that calls the OAuth redirect service:

```typescript
// Backend endpoint: /api/auth/create-github-state
app.post('/api/auth/create-github-state', async (req, res) => {
  const token = process.env.OAUTH_SERVICE_TOKEN; // Stays server-side!
  const currentAppUrl = getCurrentAppPublicUrl();
  const oauthRedirectBase = process.env.OAUTH_REDIRECT_BASE;
  
  const response = await fetch(`${oauthRedirectBase}/create-state`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      return_url: currentAppUrl
    })
  });
  
  const data = await response.json();
  res.json(data);
});
```

### 3. Handle Return from OAuth Service

When the user completes the OAuth flow, they'll be redirected back to your app with the access token:

```typescript
// On your app's landing page (e.g., after redirect)
useEffect(() => {
  const urlParams = new URLSearchParams(window.location.search);
  const githubToken = urlParams.get('github_token');
  
  if (githubToken) {
    // Token received! Now you can:
    // 1. Send it to your backend to authenticate the user
    // 2. Store it in your session
    // 3. Use it to make GitHub API requests
    
    authenticateWithGitHub(githubToken);
    
    // Clean up URL
    window.history.replaceState({}, document.title, window.location.pathname);
  }
}, []);

async function authenticateWithGitHub(token: string) {
  // Send token to your backend
  const response = await fetch('/api/auth/github/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  });
  
  if (response.ok) {
    // User is now authenticated
    console.log('Successfully authenticated with GitHub!');
  }
}
```

## React Example Component

```tsx
import { useEffect, useState } from 'react';

function GitHubLoginButton() {
  const [oauthConfig, setOauthConfig] = useState(null);
  const [loading, setLoading] = useState(false);
  
  useEffect(() => {
    // Fetch OAuth configuration from backend
    fetch('/api/auth/oauth-config')
      .then(res => res.json())
      .then(config => setOauthConfig(config));
  }, []);
  
  const handleLogin = async () => {
    if (!oauthConfig) return;
    
    setLoading(true);
    
    try {
      // Call backend to create signed state (token stays server-side!)
      const stateResponse = await fetch('/api/auth/create-github-state', {
        method: 'POST'
      });
      
      if (!stateResponse.ok) {
        throw new Error('Failed to create state parameter');
      }
      
      const { state } = await stateResponse.json();
      
      // Build GitHub authorization URL
      const authUrl = new URL('https://github.com/login/oauth/authorize');
      authUrl.searchParams.set('client_id', oauthConfig.githubClientId);
      authUrl.searchParams.set('redirect_uri', oauthConfig.githubOAuthRedirectUrl);
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('scope', 'user:email repo');
      
      // Redirect to GitHub
      window.location.href = authUrl.toString();
    } catch (error) {
      console.error('Error initiating GitHub login:', error);
      setLoading(false);
    }
  };
  
  return (
    <button onClick={handleLogin} disabled={!oauthConfig || loading}>
      {loading ? 'Redirecting...' : 'Login with GitHub'}
    </button>
  );
}
```

## Flow Diagram

```
User clicks "Login with GitHub" in frontend
  ↓
Frontend calls your backend: POST /api/auth/create-github-state
  ↓
Your backend calls OAuth redirect service (token stays server-side!)
  POST https://auth.myapp.com/create-state
  Headers: Authorization: Bearer <YOUR_TOKEN>
  Body: { return_url: "https://your-staging-app.vercel.app" }
  ↓
OAuth service validates the authentication token
  Returns to your backend: { state: "base64url_signed_state" }
  ↓
Your backend returns state to frontend
  ↓
Frontend redirects user to GitHub with:
  - redirect_uri: https://auth.myapp.com/github/callback
  - state: base64url_signed_state (cryptographically signed)
  ↓
User authorizes on GitHub
  ↓
GitHub redirects to: https://auth.myapp.com/github/callback?code=...&state=base64url_signed_state
  ↓
OAuth redirect service:
  1. Validates HMAC signature of state
  2. Checks state hasn't expired (10 min limit)
  3. Exchanges code for access token
  ↓
Service redirects back to: https://your-staging-app.vercel.app?github_token=...
  ↓
Your app receives the token and authenticates the user
```

## Security Considerations

1. **Token-Based Authentication**: Only apps with valid tokens can create signed states, eliminating domain-based vulnerabilities
2. **HMAC-Signed State**: The OAuth service uses HMAC-SHA256 to cryptographically sign state parameters, preventing attackers from forging redirect URLs
3. **State Expiration**: State parameters expire after 10 minutes, limiting the window for potential attacks
4. **CSRF Protection**: The signed state parameter provides strong CSRF protection, ensuring callbacks can only complete if initiated from your service
5. **Platform Agnostic**: Works on any hosting platform without configuration
6. **HTTPS in Production**: Always use HTTPS for production deployments
7. **Token Handling**: The access token is passed as a query parameter. Consider implementing a more secure handoff mechanism (e.g., encrypted session tokens) for production
8. **Secret Management**: 
   - Keep `OAUTH_SERVICE_TOKEN` and `STATE_SECRET` secure
   - Use different tokens for different environments
   - Never commit secrets to version control
   - Rotate tokens if compromised

## Benefits

- **Single OAuth callback URL**: Configure GitHub once, works everywhere
- **Environment agnostic**: Deploy to any platform without changing OAuth settings
- **Easy testing**: Test OAuth locally without updating GitHub settings
- **Centralized management**: Update OAuth handling in one place
