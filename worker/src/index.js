// =============================================================================
// Blog Paywall Worker
// API backend for haloowhite.com premium content system
// Handles: Stripe payments, JWT auth, content delivery, email verification
// =============================================================================

// -- Constants ----------------------------------------------------------------

const ALLOWED_ORIGINS = [
  'https://haloowhite.com',
  'http://localhost:4000',
];

const JWT_ARTICLE_TTL = 30 * 24 * 60 * 60; // 30 days in seconds

// Article slug -> Stripe Price ID mapping
// Add entries here when creating new premium articles
const ARTICLE_PRICES = {
  'arkose-funcaptcha-reverse-tutorial': 'price_arkose_article',
  'dy-vmp-tutorial': 'price_dy_abogus_article',
  // Add more: 'slug': 'price_xxx'
};

// Subscription price ID (monthly)
const SUBSCRIPTION_PRICE_ID = 'price_REPLACE_WITH_SUBSCRIPTION_PRICE_ID';

// Slug -> blog URL path mapping (for redirect after payment)
// Slug -> blog URL path mapping (must match Jekyll permalink /:year/:month/:day/:title/)
const ARTICLE_PATHS = {
  'arkose-funcaptcha-reverse-tutorial': '/2025/11/13/arkose-funcaptcha-reverse-tutorial/',
  'dy-vmp-tutorial': '/2025/08/18/dy-vmp-tutorial/',
  // Add more: 'slug': '/YYYY/MM/DD/slug/'
};

// -- CORS Helpers -------------------------------------------------------------

/**
 * Build CORS headers for the given request origin.
 * Only reflects origins in the allow-list.
 */
function corsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

/** Preflight response for OPTIONS requests. */
function handleOptions(request) {
  return new Response(null, { status: 204, headers: corsHeaders(request) });
}

/** Wrap a JSON body into a Response with CORS + content-type headers. */
function jsonResponse(data, status = 200, request = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(request),
    },
  });
}

/** Shorthand for error responses. */
function errorResponse(message, status = 400, request = null) {
  return jsonResponse({ error: message }, status, request);
}

// -- JWT (Web Crypto API, no external libs) -----------------------------------

/** Base64url-encode a buffer. */
function base64url(data) {
  return btoa(String.fromCharCode(...new Uint8Array(data)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Sign a JWT payload with HMAC-SHA256. */
async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = new TextEncoder();
  const headerB64 = base64url(enc.encode(JSON.stringify(header)));
  const payloadB64 = base64url(enc.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return `${data}.${base64url(sig)}`;
}

/** Verify a JWT and return the decoded payload, or null if invalid/expired. */
async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );

  // Restore standard base64 from base64url and decode signature
  const sigStr = sigB64.replace(/-/g, '+').replace(/_/g, '/');
  const sigBytes = Uint8Array.from(atob(sigStr), (c) => c.charCodeAt(0));

  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    sigBytes,
    enc.encode(`${headerB64}.${payloadB64}`),
  );
  if (!valid) return null;

  // Decode payload
  const payloadStr = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
  const payload = JSON.parse(atob(payloadStr));

  // Check expiration
  if (payload.exp && Date.now() / 1000 > payload.exp) return null;

  return payload;
}

// -- Stripe Helpers -----------------------------------------------------------

/**
 * Generic Stripe API call using fetch (no SDK).
 * `params` is a flat object that will be URL-encoded.
 * For nested params use Stripe's bracket notation in the keys,
 * e.g. { 'metadata[slug]': 'my-article' }.
 */
async function stripeRequest(method, path, params, secretKey) {
  const url = `https://api.stripe.com/v1${path}`;
  const headers = {
    Authorization: `Bearer ${secretKey}`,
  };

  const options = { method, headers };

  if (method === 'GET' && params) {
    const qs = new URLSearchParams(params).toString();
    const resp = await fetch(`${url}?${qs}`, options);
    return resp.json();
  }

  if (params) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    options.headers = headers;
    options.body = new URLSearchParams(params).toString();
  }

  const resp = await fetch(url, options);
  return resp.json();
}

// -- Stripe Webhook Signature Verification ------------------------------------

/**
 * Verify Stripe webhook signature (v1).
 * Returns true if valid, false otherwise.
 */
async function verifyStripeSignature(payload, sigHeader, webhookSecret) {
  const parts = sigHeader.split(',').reduce((acc, part) => {
    const [key, value] = part.split('=');
    acc[key.trim()] = value;
    return acc;
  }, {});

  const timestamp = parts['t'];
  const signature = parts['v1'];
  if (!timestamp || !signature) return false;

  // Reject events older than 5 minutes
  const age = Math.abs(Date.now() / 1000 - parseInt(timestamp, 10));
  if (age > 300) return false;

  const enc = new TextEncoder();
  const signedPayload = `${timestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(webhookSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode(signedPayload));
  const expected = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Constant-time comparison
  if (expected.length !== signature.length) return false;
  let result = 0;
  for (let i = 0; i < expected.length; i++) {
    result |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return result === 0;
}

// -- KV Purchase Records Helpers ----------------------------------------------

/**
 * Read purchase records for an email from KV.
 * Returns { articles: string[], subscription: { id, periodEnd } | null }
 */
async function getPurchaseRecords(env, email) {
  const raw = await env.PREMIUM_CONTENT.get(`purchases:${email}`);
  if (!raw) return { articles: [], subscription: null };
  try {
    return JSON.parse(raw);
  } catch {
    return { articles: [], subscription: null };
  }
}

/** Write purchase records for an email to KV. */
async function savePurchaseRecords(env, email, records) {
  await env.PREMIUM_CONTENT.put(`purchases:${email}`, JSON.stringify(records));
}

// -- Route Handlers -----------------------------------------------------------

/**
 * POST /api/checkout
 * Create a Stripe Checkout Session for article purchase or subscription.
 * Body: { slug: string, type: "article" | "subscription" }
 */
async function handleCheckout(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, request);
  }

  const { slug, type } = body;
  if (!type || !['article', 'subscription'].includes(type)) {
    return errorResponse('Invalid type. Must be "article" or "subscription".', 400, request);
  }

  const workerUrl = new URL(request.url).origin;

  // Common params
  const params = {
    'success_url': `${workerUrl}/api/callback?session_id={CHECKOUT_SESSION_ID}`,
    'cancel_url': env.BLOG_URL,
    'payment_method_types[0]': 'card',
    'payment_method_types[1]': 'wechat_pay',
    'payment_method_types[2]': 'alipay',
    'payment_method_options[wechat_pay][client]': 'web',
  };

  if (type === 'article') {
    if (!slug) {
      return errorResponse('Slug is required for article purchase.', 400, request);
    }
    const priceId = ARTICLE_PRICES[slug];
    if (!priceId) {
      return errorResponse('Unknown article slug.', 404, request);
    }
    params['mode'] = 'payment';
    params['line_items[0][price]'] = priceId;
    params['line_items[0][quantity]'] = '1';
    params['metadata[slug]'] = slug;
    params['metadata[type]'] = 'article';
  } else {
    // subscription
    params['mode'] = 'subscription';
    params['line_items[0][price]'] = SUBSCRIPTION_PRICE_ID;
    params['line_items[0][quantity]'] = '1';
    params['metadata[type]'] = 'subscription';
    if (slug) params['metadata[slug]'] = slug; // remember which article triggered it
  }

  const session = await stripeRequest('POST', '/checkout/sessions', params, env.STRIPE_SECRET_KEY);

  if (session.error) {
    console.error('Stripe checkout error:', JSON.stringify(session.error));
    return errorResponse('Failed to create checkout session.', 502, request);
  }

  return jsonResponse({ url: session.url }, 200, request);
}

/**
 * GET /api/callback?session_id=xxx
 * Stripe redirects here after successful payment.
 * Retrieves session, issues JWT, redirects user back to the blog article.
 */
async function handleCallback(request, env) {
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session_id');
  if (!sessionId) {
    return errorResponse('Missing session_id', 400, request);
  }

  // Retrieve session with expanded fields
  const session = await stripeRequest(
    'GET',
    `/checkout/sessions/${sessionId}`,
    { 'expand[0]': 'subscription' },
    env.STRIPE_SECRET_KEY,
  );

  if (session.error) {
    console.error('Stripe session retrieve error:', JSON.stringify(session.error));
    return errorResponse('Failed to retrieve session.', 502, request);
  }

  // Verify payment is actually completed (critical for async methods like WeChat/Alipay)
  if (session.payment_status !== 'paid' && session.status !== 'complete') {
    // For async payment methods, redirect to a "payment pending" state
    const slug = session.metadata?.slug || '';
    const articlePath = ARTICLE_PATHS[slug] || '/';
    return new Response(null, {
      status: 302,
      headers: { Location: `${env.BLOG_URL}${articlePath}?payment=pending` },
    });
  }

  const email = session.customer_details?.email || session.customer_email;
  if (!email) {
    return errorResponse('No email found in session.', 400, request);
  }

  const paymentType = session.metadata?.type || 'article';
  const slug = session.metadata?.slug || '';

  // Build JWT payload
  const now = Math.floor(Date.now() / 1000);
  let payload;

  if (paymentType === 'subscription' && session.subscription) {
    const sub = typeof session.subscription === 'string' ? null : session.subscription;
    const periodEnd = sub?.current_period_end || now + JWT_ARTICLE_TTL;
    payload = {
      email,
      type: 'subscription',
      iat: now,
      exp: periodEnd,
    };
  } else {
    // Single article purchase
    payload = {
      email,
      type: 'article',
      articles: slug ? [slug] : [],
      iat: now,
      exp: now + JWT_ARTICLE_TTL,
    };
  }

  const token = await signJWT(payload, env.JWT_SECRET);

  // Determine redirect path
  const articlePath = ARTICLE_PATHS[slug] || '/';
  const redirectUrl = `${env.BLOG_URL}${articlePath}#token=${token}`;

  return new Response(null, {
    status: 302,
    headers: {
      Location: redirectUrl,
      ...corsHeaders(request),
    },
  });
}

/**
 * GET /api/content/:slug
 * Deliver premium content from KV.
 * Requires valid JWT in Authorization header with proper entitlement.
 */
async function handleContent(request, env) {
  const url = new URL(request.url);
  const slug = url.pathname.replace('/api/content/', '');

  if (!slug) {
    return errorResponse('Missing slug', 400, request);
  }

  // Extract JWT from Authorization header
  const authHeader = request.headers.get('Authorization') || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return errorResponse('Missing or invalid Authorization header.', 401, request);
  }

  const token = match[1];
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) {
    return errorResponse('Invalid or expired token.', 401, request);
  }

  // Check entitlement
  const hasAccess =
    payload.type === 'subscription' ||
    (Array.isArray(payload.articles) && payload.articles.includes(slug));

  if (!hasAccess) {
    return errorResponse('You do not have access to this article.', 403, request);
  }

  // Fetch premium content from KV
  const html = await env.PREMIUM_CONTENT.get(slug);
  if (!html) {
    return errorResponse('Content not found.', 404, request);
  }

  return jsonResponse({ html }, 200, request);
}

/**
 * POST /api/restore
 * Send a verification code to the user's email for access restoration.
 * Body: { email: string }
 */
async function handleRestore(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, request);
  }

  const { email } = body;
  if (!email || !email.includes('@')) {
    return errorResponse('Valid email is required.', 400, request);
  }

  // Rate limit: max 3 restore requests per email per hour
  const restoreKey = `ratelimit:restore:${email}`;
  const restoreCount = parseInt(await env.VERIFY_CODES.get(restoreKey) || '0', 10);
  if (restoreCount >= 3) {
    return errorResponse('Too many requests. Please try again later.', 429, request);
  }
  await env.VERIFY_CODES.put(restoreKey, String(restoreCount + 1), { expirationTtl: 3600 });

  // Generate 6-digit code
  const code = String(Math.floor(100000 + Math.random() * 900000));

  // Store in KV with 10-minute TTL
  await env.VERIFY_CODES.put(email, code, { expirationTtl: 600 });

  // Send verification email via Resend
  const resendResp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: "White's Blog <noreply@haloowhite.com>",
      to: email,
      subject: "验证码 - White's Blog",
      html: `<p>您的验证码是：<strong>${code}</strong></p><p>有效期 10 分钟。</p>`,
    }),
  });

  if (!resendResp.ok) {
    const err = await resendResp.text();
    console.error('Resend API error:', err);
    return errorResponse('Failed to send verification email.', 502, request);
  }

  return jsonResponse({ success: true }, 200, request);
}

/**
 * POST /api/verify
 * Verify the email code and issue a JWT with all entitlements.
 * Body: { email: string, code: string }
 */
async function handleVerify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, request);
  }

  const { email, code } = body;
  if (!email || !code) {
    return errorResponse('Email and code are required.', 400, request);
  }

  // Rate limit: max 5 verify attempts per email per 10 minutes
  const attemptKey = `ratelimit:verify:${email}`;
  const attempts = parseInt(await env.VERIFY_CODES.get(attemptKey) || '0', 10);
  if (attempts >= 5) {
    return errorResponse('Too many attempts. Please request a new code.', 429, request);
  }
  await env.VERIFY_CODES.put(attemptKey, String(attempts + 1), { expirationTtl: 600 });

  // Check code
  const storedCode = await env.VERIFY_CODES.get(email);
  if (!storedCode || storedCode !== code) {
    return errorResponse('Invalid or expired verification code.', 400, request);
  }

  // Delete used code
  await env.VERIFY_CODES.delete(email);

  // Read purchase records from KV (populated by webhook)
  const records = await getPurchaseRecords(env, email);

  // Build JWT with all entitlements
  const now = Math.floor(Date.now() / 1000);
  let payload;

  if (records.subscription && records.subscription.periodEnd > now) {
    // Active subscription
    payload = {
      email,
      type: 'subscription',
      iat: now,
      exp: records.subscription.periodEnd,
    };
  } else if (records.articles && records.articles.length > 0) {
    // Individual article purchases
    payload = {
      email,
      type: 'article',
      articles: records.articles,
      iat: now,
      exp: now + JWT_ARTICLE_TTL,
    };
  } else {
    return errorResponse('No purchases found for this email.', 404, request);
  }

  const token = await signJWT(payload, env.JWT_SECRET);
  return jsonResponse({ token }, 200, request);
}

/**
 * POST /api/webhook
 * Handle Stripe webhook events.
 * Events: checkout.session.completed, customer.subscription.deleted
 */
async function handleWebhook(request, env) {
  const body = await request.text();
  const sigHeader = request.headers.get('stripe-signature') || '';

  // Verify webhook signature
  const valid = await verifyStripeSignature(body, sigHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!valid) {
    return new Response('Invalid signature', { status: 400 });
  }

  let event;
  try {
    event = JSON.parse(body);
  } catch {
    return new Response('Invalid JSON', { status: 400 });
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const email = session.customer_details?.email || session.customer_email;
      if (!email) {
        console.error('Webhook: no email in checkout session');
        break;
      }

      const paymentType = session.metadata?.type || 'article';
      const slug = session.metadata?.slug || '';

      // Read existing records
      const records = await getPurchaseRecords(env, email);

      if (paymentType === 'subscription') {
        // For subscription, retrieve the subscription object to get period end
        let periodEnd = Math.floor(Date.now() / 1000) + JWT_ARTICLE_TTL; // fallback
        if (session.subscription) {
          const subId =
            typeof session.subscription === 'string'
              ? session.subscription
              : session.subscription.id;
          const sub = await stripeRequest('GET', `/subscriptions/${subId}`, null, env.STRIPE_SECRET_KEY);
          if (sub && sub.current_period_end) {
            periodEnd = sub.current_period_end;
          }
          records.subscription = { id: subId, periodEnd };
        } else {
          records.subscription = { id: null, periodEnd };
        }
      } else {
        // Article purchase - add slug to purchased list
        if (slug && !records.articles.includes(slug)) {
          records.articles.push(slug);
        }
      }

      await savePurchaseRecords(env, email, records);
      break;
    }

    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      const customerId = subscription.customer;

      // Look up customer email
      const customer = await stripeRequest('GET', `/customers/${customerId}`, null, env.STRIPE_SECRET_KEY);
      const email = customer?.email;
      if (!email) {
        console.error('Webhook: no email for customer', customerId);
        break;
      }

      // Remove subscription from records (keep article purchases)
      const records = await getPurchaseRecords(env, email);
      records.subscription = null;
      await savePurchaseRecords(env, email, records);
      break;
    }

    default:
      // Unhandled event type - ignore
      break;
  }

  return new Response('OK', { status: 200 });
}

// -- Main Fetch Handler -------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return handleOptions(request);
    }

    try {
      // Route matching
      if (path === '/api/checkout' && request.method === 'POST') {
        return await handleCheckout(request, env);
      }
      if (path === '/api/callback' && request.method === 'GET') {
        return await handleCallback(request, env);
      }
      if (path.startsWith('/api/content/') && request.method === 'GET') {
        return await handleContent(request, env);
      }
      if (path === '/api/restore' && request.method === 'POST') {
        return await handleRestore(request, env);
      }
      if (path === '/api/verify' && request.method === 'POST') {
        return await handleVerify(request, env);
      }
      if (path === '/api/webhook' && request.method === 'POST') {
        return await handleWebhook(request, env);
      }

      return jsonResponse({ error: 'Not Found' }, 404, request);
    } catch (err) {
      console.error('Unhandled error:', err.message, err.stack);
      return errorResponse('Internal Server Error', 500, request);
    }
  },
};
