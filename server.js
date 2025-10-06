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
        <h2>Callback URL:</h2>
        <code>${callbackUrl}</code>
        <h2>Return URL:</h2>
        <code>${returnUrl}</code>
        <p><a href="${authUrl.toString()}">🚀 Test GitHub OAuth Flow</a></p>
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
      <body>
        <h1>GitHub OAuth Redirect Service</h1>
        <ul>
          <li><a href="/github/test">Test OAuth Flow</a></li>
          <li><a href="/health">Health Check</a></li>
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
