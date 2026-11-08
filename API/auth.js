"use strict";

/**
 * CUSTOMER HUNT
 * Authentication API
 *
 * Runtime: Vercel Node.js
 * Database: Layerbase PostgreSQL
 * Authentication: Better Auth
 *
 * Supported actions:
 * - signup
 * - login
 * - logout
 */

let authInitialization = null;

const MAX_REQUEST_BYTES = 16 * 1024;

/**
 * Validate and normalize an application origin.
 */
function normalizeOrigin(value, allowLocalhost = true) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error("An application origin is invalid.");
  }

  let parsed;

  try {
    parsed = new URL(value.trim());
  } catch {
    throw new Error("An application origin is invalid.");
  }

  const isLocalhost = [
    "localhost",
    "127.0.0.1",
    "::1"
  ].includes(parsed.hostname);

  if (
    parsed.protocol !== "https:" &&
    !(allowLocalhost && isLocalhost && parsed.protocol === "http:")
  ) {
    throw new Error("Application origins must use HTTPS.");
  }

  if (
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error("Application origins must contain only an origin.");
  }

  return parsed.origin;
}

/**
 * Read and validate required environment variables.
 */
function getConfiguration() {
  const databaseUrl = process.env.DATABASE_URL;
  const authSecret = process.env.BETTER_AUTH_SECRET;
  const authUrl = process.env.BETTER_AUTH_URL;

  if (!databaseUrl) {
    throw new Error("DATABASE_URL is not configured.");
  }

  if (!authSecret || authSecret.length < 32) {
    throw new Error(
      "BETTER_AUTH_SECRET must contain at least 32 characters."
    );
  }

  if (!authUrl) {
    throw new Error("BETTER_AUTH_URL is not configured.");
  }

  const normalizedAuthUrl = normalizeOrigin(authUrl);

  const additionalOrigins = (
    process.env.BETTER_AUTH_TRUSTED_ORIGINS || ""
  )
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean)
    .map(origin => normalizeOrigin(origin));

  const trustedOrigins = [
    normalizedAuthUrl,
    ...additionalOrigins
  ];

  return {
    databaseUrl,
    authSecret,
    authUrl: normalizedAuthUrl,
    trustedOrigins: [...new Set(trustedOrigins)]
  };
}

/**
 * Convert incoming Node.js headers into Web Headers.
 */
function convertHeaders(incomingHeaders) {
  const headers = new Headers();

  for (const [name, value] of Object.entries(incomingHeaders || {})) {
    if (value === undefined || value === null) {
      continue;
    }

    headers.set(
      name,
      Array.isArray(value) ? value.join(", ") : String(value)
    );
  }

  return headers;
}

/**
 * Create the Better Auth instance once per serverless instance.
 */
async function getAuth() {
  if (!authInitialization) {
    authInitialization = initializeAuth().catch(error => {
      authInitialization = null;
      throw error;
    });
  }

  return authInitialization;
}

/**
 * Initialize PostgreSQL and Better Auth.
 */
async function initializeAuth() {
  const config = getConfiguration();

  const [betterAuthModule, pgModule] = await Promise.all([
    import("better-auth"),
    import("pg")
  ]);

  const betterAuth = betterAuthModule.betterAuth;
  const Pool = pgModule.Pool || pgModule.default?.Pool;

  if (typeof betterAuth !== "function" || !Pool) {
    throw new Error(
      "Authentication dependencies could not be initialized."
    );
  }

  const pool = new Pool({
    connectionString: config.databaseUrl,
    max: 2,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 10000,
    allowExitOnIdle: true
  });

  pool.on("error", () => {
    // Database details must never be exposed to clients.
  });

  const auth = betterAuth({
    appName: "Customer Hunt",

    baseURL: config.authUrl,

    basePath: "/api/auth",

    secret: config.authSecret,

    trustedOrigins: config.trustedOrigins,

    database: pool,

    emailAndPassword: {
      enabled: true,
      minPasswordLength: 12,
      maxPasswordLength: 128
    },

    rateLimit: {
      enabled: true,

      window: 60,

      max: 100,

      storage: "database",

      customRules: {
        "/sign-in/email": {
          window: 60,
          max: 5
        },

        "/sign-up/email": {
          window: 3600,
          max: 5
        }
      }
    }
  });

  return {
    auth,
    pool
  };
}

/**
 * Parse the request body safely.
 */
function parseRequestBody(req) {
  if (req.body && typeof req.body === "object") {
    if (Buffer.isBuffer(req.body)) {
      try {
        return JSON.parse(req.body.toString("utf8"));
      } catch {
        return null;
      }
    }

    return req.body;
  }

  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch {
      return null;
    }
  }

  return null;
}
/**
 * Validate request content type and size.
 */
function validateRequestFormat(req, body) {
  const contentType = String(
    req.headers["content-type"] || ""
  ).toLowerCase();

  if (!/^application\/json(?:\s*;|$)/.test(contentType)) {
    return false;
  }

  const contentLength = Number(
    req.headers["content-length"] || 0
  );

  if (
    Number.isFinite(contentLength) &&
    contentLength > MAX_REQUEST_BYTES
  ) {
    return false;
  }

  let serialized;

  try {
    serialized = JSON.stringify(body);
  } catch {
    return false;
  }

  if (
    typeof serialized !== "string" ||
    Buffer.byteLength(serialized, "utf8") > MAX_REQUEST_BYTES
  ) {
    return false;
  }

  return true;
}

/**
 * Validate browser request origin.
 *
 * Browser requests from the application must originate from
 * an explicitly trusted origin.
 */
function verifyRequestOrigin(req, trustedOrigins) {
  const origin = req.headers.origin;

  if (origin) {
    let normalizedOrigin;

    try {
      normalizedOrigin = normalizeOrigin(origin);
    } catch {
      return false;
    }

    return trustedOrigins.includes(normalizedOrigin);
  }

  const fetchSite = String(
    req.headers["sec-fetch-site"] || ""
  ).toLowerCase();

  if (fetchSite === "cross-site") {
    return false;
  }

  return true;
}

/**
 * Validate email addresses.
 */
function normalizeEmail(value) {
  if (typeof value !== "string") {
    return null;
  }

  const email = value.trim().toLowerCase();

  if (email.length > 254) {
    return null;
  }

  const emailPattern =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!emailPattern.test(email)) {
    return null;
  }

  return email;
}

/**
 * Validate passwords without changing their contents.
 */
function validatePassword(value) {
  if (typeof value !== "string") {
    return false;
  }

  return (
    value.length >= 12 &&
    value.length <= 128
  );
}

/**
 * Validate a user's display name.
 */
function normalizeName(value) {
  if (typeof value !== "string") {
    return null;
  }

  const name = value.trim();

  if (name.length < 2 || name.length > 100) {
    return null;
  }

  if (/[\u0000-\u001F\u007F]/.test(name)) {
    return null;
  }

  return name;
}

/**
 * Send a consistent JSON response.
 */
function sendJson(res, statusCode, payload) {
  if (res.headersSent || res.writableEnded) {
    return;
  }

  res.statusCode = statusCode;

  res.setHeader(
    "Content-Type",
    "application/json; charset=utf-8"
  );

  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate"
  );

  res.setHeader("Pragma", "no-cache");

  res.end(JSON.stringify(payload));
}

/**
 * Forward authentication cookies to the browser.
 */
function forwardCookies(res, result) {
  if (!result || !result.headers) {
    return;
  }

  const responseHeaders = result.headers;

  let cookies = [];

  if (typeof responseHeaders.getSetCookie === "function") {
    cookies = responseHeaders.getSetCookie();
  } else {
    const cookie = responseHeaders.get("set-cookie");

    if (cookie) {
      cookies = [cookie];
    }
  }

  if (cookies.length > 0) {
    res.setHeader("Set-Cookie", cookies);
  }
}

/**
 * Validate the Better Auth response before using its user object.
 */
function getAuthenticatedUser(result) {
  const response = result?.response;

  if (
    !response ||
    !response.user ||
    typeof response.user.id !== "string"
  ) {
    throw new Error("Authentication returned an invalid user.");
  }

  return {
    id: response.user.id,
    name: response.user.name || "",
    email: response.user.email || ""
  };
}

/**
 * Convert authentication failures into safe responses.
 */
function handleAuthError(res, error) {
  const status = Number(
    error?.status ||
    error?.statusCode ||
    500
  );

  if (status === 401) {
    return sendJson(res, 401, {
      success: false,
      error: "Email or password is incorrect."
    });
  }

  if (status === 422) {
    return sendJson(res, 422, {
      success: false,
      error: "The account already exists or the submitted information is invalid."
    });
  }

  if (status === 429) {
    return sendJson(res, 429, {
      success: false,
      error: "Too many attempts. Please try again later."
    });
  }

  if (status >= 400 && status < 500) {
    return sendJson(res, status, {
      success: false,
      error: "The authentication request could not be completed."
    });
  }

  return sendJson(res, 500, {
    success: false,
    error: "Authentication is temporarily unavailable."
  });
}
/**
 * REGISTER A NEW CUSTOMER HUNT USER
 *
 * Frontend request:
 *
 * {
 *   action: "signup",
 *   email: "user@example.com",
 *   password: "a-secure-password",
 *   fullName: "Customer Name"
 * }
 */
async function signup(auth, req, res, body) {
  const email = normalizeEmail(body.email);
  const password = body.password;
  const name = normalizeName(body.fullName);

  if (!name) {
    return sendJson(res, 400, {
      success: false,
      error: "Enter a valid full name."
    });
  }

  if (!email) {
    return sendJson(res, 400, {
      success: false,
      error: "Enter a valid email address."
    });
  }

  if (!validatePassword(password)) {
    return sendJson(res, 400, {
      success: false,
      error: "Your password must contain between 12 and 128 characters."
    });
  }

  const result = await auth.api.signUpEmail({
    body: {
      name,
      email,
      password
    },

    headers: convertHeaders(req.headers),

    returnHeaders: true
  });

  const user = getAuthenticatedUser(result);

  forwardCookies(res, result);

  return sendJson(res, 201, {
    success: true,
    redirect: "/dashboard.html",
    user
  });
}

/**
 * SIGN IN AN EXISTING CUSTOMER HUNT USER
 *
 * Frontend request:
 *
 * {
 *   action: "login",
 *   email: "user@example.com",
 *   password: "a-secure-password",
 *   rememberMe: true
 * }
 */
async function login(auth, req, res, body) {
  const email = normalizeEmail(body.email);
  const password = body.password;

  if (!email) {
    return sendJson(res, 400, {
      success: false,
      error: "Enter a valid email address."
    });
  }

  if (!validatePassword(password)) {
    return sendJson(res, 400, {
      success: false,
      error: "Enter a valid password."
    });
  }

  const rememberMe = body.rememberMe !== false;

  const result = await auth.api.signInEmail({
    body: {
      email,
      password,
      rememberMe
    },

    headers: convertHeaders(req.headers),

    returnHeaders: true
  });

  const user = getAuthenticatedUser(result);

  forwardCookies(res, result);

  return sendJson(res, 200, {
    success: true,
    redirect: "/dashboard.html",
    user
  });
}

/**
 * SIGN OUT THE CURRENT USER
 *
 * Frontend request:
 *
 * {
 *   action: "logout"
 * }
 */
async function logout(auth, req, res) {
  const result = await auth.api.signOut({
    headers: convertHeaders(req.headers),
    returnHeaders: true
  });

  forwardCookies(res, result);

  return sendJson(res, 200, {
    success: true,
    message: "You have been signed out."
  });
}
/**
 * MAIN VERCEL SERVERLESS HANDLER
 */
module.exports = async function authHandler(req, res) {
  res.setHeader("X-Content-Type-Options", "nosniff");

  res.setHeader("Referrer-Policy", "same-origin");

  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");

    return sendJson(res, 405, {
      success: false,
      error: "Method not allowed."
    });
  }

  if (
    !validateRequestFormat(
      req,
      parseRequestBody(req) || {}
    )
  ) {
    return sendJson(res, 400, {
      success: false,
      error: "Invalid request format."
    });
  }

  const body = parseRequestBody(req);

  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return sendJson(res, 400, {
      success: false,
      error: "Invalid request body."
    });
  }

  const action = body.action;

  if (
    typeof action !== "string" ||
    !["signup", "login", "logout"].includes(action)
  ) {
    return sendJson(res, 400, {
      success: false,
      error: "Invalid authentication action."
    });
  }

  try {
    const config = getConfiguration();

    if (!verifyRequestOrigin(req, config.trustedOrigins)) {
      return sendJson(res, 403, {
        success: false,
        error: "This request origin is not permitted."
      });
    }

    const { auth } = await getAuth();

    switch (action) {
      case "signup":
        return await signup(auth, req, res, body);

      case "login":
        return await login(auth, req, res, body);

      case "logout":
        return await logout(auth, req, res);

      default:
        return sendJson(res, 400, {
          success: false,
          error: "Invalid authentication action."
        });
    }

  } catch (error) {
    return handleAuthError(res, error);
  }
};
