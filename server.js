import express from 'express';
import crypto from 'crypto';

const app = express();
app.use(express.json());

// Trust proxy - important for getting correct protocol on Render, Heroku, etc.
app.set('trust proxy', true);

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

function getCallbackUrl(req) {
  // For production hosting (Render, Heroku, etc.), force HTTPS
  const protocol = req.get('x-forwarded-proto') || req.protocol;
  const host = req.get('host');
  
  // If deployed (not localhost), force https
  const finalProtocol = host.includes('localhost') ? protocol : 'https';
  
  return `${finalProtocol}://${host}/github/callback`;
}
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
  const callbackUrl = getCallbackUrl(req);
  
  console.log('=== GitHub OAuth Debug ===');
  console.log('Callback URL being sent to GitHub:', callbackUrl);
  console.log('Return URL from request:', return_url);
  console.log('X-Forwarded-Proto:', req.get('x-forwarded-proto'));
  console.log('Request protocol:', req.protocol);
  console.log('Request host:', req.get('host'));
  console.log('=========================');
  
  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', callbackUrl);
  authUrl.searchParams.set('state', signedState);
  authUrl.searchParams.set('scope', scope || 'repo workflow');
  
  res.json({ 
    authorize_url: authUrl.toString(),
    state: signedState,
    debug: {
      callback_url: callbackUrl,
      return_url: return_url,
      scope: scope || 'repo workflow'
    }
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

app.get('/github/test', (req, res) => {
  const returnUrl = req.query.return_url || APP_REDIRECT_FALLBACK;
  
  const signedState = createSignedState(returnUrl);
  const callbackUrl = getCallbackUrl(req);
  
  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', callbackUrl);
  authUrl.searchParams.set('state', signedState);
  authUrl.searchParams.set('scope', 'repo workflow');
  
  console.log('=== GitHub OAuth Test Debug ===');
  console.log('Callback URL:', callbackUrl);
  console.log('Return URL:', returnUrl);
  console.log('Scope:', 'repo workflow');
  console.log('X-Forwarded-Proto:', req.get('x-forwarded-proto'));
  console.log('Protocol:', req.protocol);
  console.log('Host:', req.get('host'));
  console.log('Full Auth URL:', authUrl.toString());
  console.log('===============================');
  
  res.send(`
    <html>
      <head><title>GitHub OAuth Test</title></head>
      <body style="font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px;">
        <h1>GitHub OAuth Test Page</h1>
        <p>This is a test endpoint that doesn't require authentication.</p>
        
        <h2>GitHub Permissions Requested:</h2>
        <ul>
          <li><strong>repo</strong> - Full control of private repositories (read/write, create branches)</li>
          <li><strong>workflow</strong> - Update GitHub Action workflows (create and trigger workflows)</li>
        </ul>
        
        <h2>Configuration:</h2>
        <ul>
          <li><strong>Callback URL:</strong> <code>${callbackUrl}</code></li>
          <li><strong>Return URL:</strong> <code>${returnUrl}</code></li>
          <li><strong>GitHub Client ID:</strong> <code>${GITHUB_CLIENT_ID}</code></li>
          <li><strong>Scopes:</strong> <code>repo workflow</code></li>
        </ul>
        
        <h2>Permissions Requested:</h2>
        <ul>
          <li>✓ <strong>repo</strong> - Full repository access (read/write, create branches)</li>
          <li>✓ <strong>workflow</strong> - Create and trigger GitHub Actions workflows</li>
        </ul>
        
        <h2>⚠️ Important:</h2>
        <p>Make sure the callback URL above is registered in your GitHub OAuth App settings!</p>
        <p>Go to: GitHub → Settings → Developer settings → OAuth Apps → Your App</p>
        <p>Set the <strong>Authorization callback URL</strong> to: <code>${callbackUrl}</code></p>
        
        <div style="margin: 30px 0;">
          <a href="${authUrl.toString()}" 
             style="display: inline-block; background: #24292e; color: white; padding: 12px 24px; 
                    text-decoration: none; border-radius: 6px; font-weight: bold;">
            🚀 Test GitHub OAuth Flow
          </a>
        </div>
        
        <h2>Debug Information:</h2>
        <pre style="background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto;">${JSON.stringify({
          callback_url: callbackUrl,
          return_url: returnUrl,
          client_id: GITHUB_CLIENT_ID,
          protocol: req.protocol,
          host: req.get('host'),
          full_auth_url: authUrl.toString()
        }, null, 2)}</pre>
        
        <h2>How to Use:</h2>
        <ol>
          <li>Click the button above to start the OAuth flow</li>
          <li>GitHub will ask you to authorize the app</li>
          <li>After authorization, you'll be redirected back with a token</li>
          <li>The token will be appended to the return URL as a query parameter</li>
        </ol>
        
        <h2>Custom Return URL:</h2>
        <p>Add <code>?return_url=YOUR_URL</code> to this page URL to test with a custom return URL.</p>
        <p>Example: <code>/github/test?return_url=http://localhost:3000/success</code></p>
      </body>
    </html>
  `);
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
          <li><code>GET /github/test</code> - Test GitHub OAuth flow without authentication (for debugging)</li>
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
        <h2>Quick Test:</h2>
        <p><a href="/github/test" style="color: #0366d6;">Go to test page →</a></p>
      </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`OAuth Redirect Service running on port ${PORT}`);
  console.log(`GitHub callback URL: http://localhost:${PORT}/github/callback`);
  console.log(`OAuth service token configured: ${!!OAUTH_SERVICE_TOKEN}`);
});
