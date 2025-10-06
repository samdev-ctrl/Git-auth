import express from 'express';
import crypto from 'crypto';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const APP_REDIRECT_FALLBACK = process.env.APP_REDIRECT_FALLBACK || 'http://localhost:3000';
const OAUTH_SERVICE_TOKEN = process.env.OAUTH_SERVICE_TOKEN;

if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
  console.error('ERROR: GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set');
  process.exit(1);
}

if (!OAUTH_SERVICE_TOKEN) {
  console.error('ERROR: OAUTH_SERVICE_TOKEN not configured. Set OAUTH_SERVICE_TOKEN environment variable.');
  console.error('Generate token with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

function validateToken(token) {
  if (!token || !OAUTH_SERVICE_TOKEN) return false;
  return token === OAUTH_SERVICE_TOKEN;
}

function createSignedState(returnUrl) {
  const timestamp = Date.now();
  const payload = JSON.stringify({ url: returnUrl, timestamp });
  const signature = crypto
    .createHmac('sha256', OAUTH_SERVICE_TOKEN)
    .update(payload)
    .digest('hex');
  
  return Buffer.from(JSON.stringify({ payload, signature })).toString('base64url');
}

function verifySignedState(signedState) {
  try {
    const decoded = JSON.parse(Buffer.from(signedState, 'base64url').toString());
    const { payload, signature } = decoded;
    
    const expectedSignature = crypto
      .createHmac('sha256', OAUTH_SERVICE_TOKEN)
      .update(payload)
      .digest('hex');
    
    if (signature !== expectedSignature) {
      return { valid: false, error: 'Invalid signature' };
    }
    
    const data = JSON.parse(payload);
    const age = Date.now() - data.timestamp;
    
    if (age > 10 * 60 * 1000) {
      return { valid: false, error: 'State expired (>10 minutes)' };
    }
    
    return { valid: true, url: data.url };
  } catch (error) {
    return { valid: false, error: 'Invalid state format' };
  }
}

app.get('/github/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).send('Missing authorization code');
  }

  if (!state) {
    return res.status(400).send('Missing state parameter');
  }

  const stateVerification = verifySignedState(state);
  
  if (!stateVerification.valid) {
    console.error('State verification failed:', stateVerification.error);
    return res.status(403).send(`Invalid state parameter: ${stateVerification.error}`);
  }

  try {
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
      }),
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      console.error('GitHub OAuth error:', tokenData);
      return res.status(400).send(`GitHub OAuth error: ${tokenData.error_description || tokenData.error}`);
    }

    const accessToken = tokenData.access_token;

    if (!accessToken) {
      console.error('No access token received from GitHub');
      return res.status(500).send('Failed to obtain access token');
    }

    const url = new URL(stateVerification.url);
    url.searchParams.set('github_token', accessToken);

    console.log(`Redirecting to: ${url.toString()}`);
    res.redirect(url.toString());

  } catch (error) {
    console.error('Error during OAuth callback:', error);
    res.status(500).send('Internal server error during OAuth callback');
  }
});

app.post('/github/authorize-url', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  
  if (!validateToken(token)) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or missing token' });
  }
  
  const { return_url, scope } = req.body;
  
  if (!return_url) {
    return res.status(400).json({ error: 'Missing return_url in request body' });
  }
  
  if (!return_url.startsWith('http://') && !return_url.startsWith('https://')) {
    return res.status(400).json({ error: 'Invalid return_url format' });
  }
  
  const signedState = createSignedState(return_url);
  
  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', `${req.protocol}://${req.get('host')}/github/callback`);
  authUrl.searchParams.set('state', signedState);
  authUrl.searchParams.set('scope', scope || 'user:email');
  
  res.json({ 
    authorize_url: authUrl.toString(),
    state: signedState
  });
});

app.post('/create-state', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  
  if (!validateToken(token)) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or missing token' });
  }
  
  const { return_url } = req.body;
  
  if (!return_url) {
    return res.status(400).json({ error: 'Missing return_url in request body' });
  }
  
  if (!return_url.startsWith('http://') && !return_url.startsWith('https://')) {
    return res.status(400).json({ error: 'Invalid return_url format' });
  }
  
  const signedState = createSignedState(return_url);
  res.json({ state: signedState });
});


app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'oauth-redirect-service',
    tokenConfigured: !!OAUTH_SERVICE_TOKEN,
    githubConfigured: !!(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET)
  });
});

app.get('/', (req, res) => {
  res.send(`
    <html>
      <head><title>OAuth Redirect Service</title></head>
      <body style="font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
        <h1>GitHub OAuth Redirect Service</h1>
        <p>This service handles GitHub OAuth callbacks and redirects users back to their original environment.</p>
        <h2>Available Endpoints:</h2>
        <ul>
          <li><code>GET /github/callback</code> - GitHub OAuth callback handler (requires signed state)</li>
          <li><code>POST /github/authorize-url</code> - Get full GitHub authorization URL (requires Bearer token auth, server-side only!)</li>
          <li><code>POST /create-state</code> - Create signed state (legacy endpoint, requires Bearer token auth)</li>
          <li><code>GET /health</code> - Health check endpoint</li>
        </ul>
        <h2>Configuration:</h2>
        <ul>
          <li>GITHUB_CLIENT_ID: ${GITHUB_CLIENT_ID ? '✓ Set' : '✗ Missing'}</li>
          <li>GITHUB_CLIENT_SECRET: ${GITHUB_CLIENT_SECRET ? '✓ Set' : '✗ Missing'}</li>
          <li>OAUTH_SERVICE_TOKEN: ${OAUTH_SERVICE_TOKEN ? '✓ Set' : '✗ Missing'}</li>
        </ul>
        <h2>Security Features:</h2>
        <ul>
          <li>✓ Single-token architecture (OAUTH_SERVICE_TOKEN for auth + state signing)</li>
          <li>✓ Token-based authentication (no domain allowlists)</li>
          <li>✓ HMAC-signed state parameter validation</li>
          <li>✓ State expiration (10 minutes)</li>
          <li>✓ CSRF protection via cryptographic state</li>
          <li>✓ Works on any hosting platform</li>
        </ul>
        <h2>Simplified Architecture:</h2>
        <p>Your main app only needs 2 environment variables:</p>
        <ul>
          <li><code>OAUTH_REDIRECT_BASE</code> - URL of this service</li>
          <li><code>OAUTH_SERVICE_TOKEN</code> - Same token configured here</li>
        </ul>
      </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`OAuth Redirect Service running on port ${PORT}`);
  console.log(`GitHub callback URL: http://localhost:${PORT}/github/callback`);
  console.log(`OAuth service token configured: ${!!OAUTH_SERVICE_TOKEN}`);
});
