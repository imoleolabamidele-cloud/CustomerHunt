"use strict";

/**
 * CUSTOMER HUNT
 * Product Management API
 *
 * Runtime: Vercel Node.js
 * Database: Layerbase PostgreSQL
 * Authentication: Better Auth
 *
 * Supported methods:
 * GET  /api/create-product
 * POST /api/create-product
 *
 * GET:
 * Returns the authenticated user's active products.
 *
 * POST:
 * Creates a new product.
 */

const crypto = require("node:crypto");

let initializationPromise = null;
let schemaPromise = null;

/**
 * Read and validate application configuration.
 */
function getConfiguration() {
  const databaseUrl = process.env.DATABASE_URL;
  const authSecret = process.env.BETTER_AUTH_SECRET;
  const authUrl = process.env.BETTER_AUTH_URL;

  if (!databaseUrl) {
    throw new Error("DATABASE_URL is not configured.");
  }

  if (!authSecret || authSecret.length < 32) {
    throw new Error("BETTER_AUTH_SECRET is invalid.");
  }

  if (!authUrl) {
    throw new Error("BETTER_AUTH_URL is not configured.");
  }

  const normalizeOrigin = value => {
    let parsed;

    try {
      parsed = new URL(value);
    } catch {
      throw new Error("A trusted application origin is invalid.");
    }

    const isLocalhost = [
      "localhost",
      "127.0.0.1",
      "::1",
      "[::1]"
    ].includes(parsed.hostname);

    if (
      parsed.protocol !== "https:" &&
      !(parsed.protocol === "http:" && isLocalhost)
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
  };

  const normalizedAuthUrl = normalizeOrigin(authUrl);

  const additionalOrigins = (
    process.env.BETTER_AUTH_TRUSTED_ORIGINS || ""
  )
    .split(",")
    .map(value => value.trim())
    .filter(Boolean)
    .map(normalizeOrigin);

  return {
    databaseUrl,
    authSecret,
    authUrl: normalizedAuthUrl,
    trustedOrigins: [
      ...new Set([
        normalizedAuthUrl,
        ...additionalOrigins
      ])
    ]
  };
}

/**
 * Convert incoming request headers into Web Headers.
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
 * Initialize Better Auth and PostgreSQL.
 */
async function initializeApplication() {
  const config = getConfiguration();

  const [betterAuthModule, pgModule] = await Promise.all([
    import("better-auth"),
    import("pg")
  ]);

  const betterAuth = betterAuthModule.betterAuth;
  const Pool = pgModule.Pool || pgModule.default?.Pool;

  if (typeof betterAuth !== "function" || !Pool) {
    throw new Error(
      "Application database dependencies are unavailable."
    );
  }

  const pool = new Pool({
    connectionString: config.databaseUrl,
    max: 3,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 10000,
    allowExitOnIdle: true
  });

  pool.on("error", () => {
    // Do not expose database errors to clients.
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
    }
  });

  return {
    auth,
    pool,
    config
  };
}

/**
 * Reuse initialized application resources.
 */
async function getApplication() {
  if (!initializationPromise) {
    initializationPromise = initializeApplication().catch(error => {
      initializationPromise = null;
      throw error;
    });
  }

  return initializationPromise;
}

/**
 * Create the Customer Hunt application tables.
 *
 * Better Auth's user/session tables must already exist
 * through the Better Auth migration process.
 */
async function ensureDatabaseSchema(pool) {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS customer_hunt_products (
          id UUID PRIMARY KEY,

          user_id TEXT NOT NULL,

          name VARCHAR(120) NOT NULL,

          target_location VARCHAR(100) NOT NULL,

          is_active BOOLEAN NOT NULL DEFAULT TRUE,

          last_opened_at TIMESTAMPTZ,

          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

          CONSTRAINT customer_hunt_products_name_check
            CHECK (char_length(trim(name)) BETWEEN 1 AND 120),

          CONSTRAINT customer_hunt_products_location_check
            CHECK (char_length(trim(target_location)) BETWEEN 1 AND 100)
        );

        ALTER TABLE customer_hunt_products
          ADD COLUMN IF NOT EXISTS last_opened_at TIMESTAMPTZ;

        CREATE INDEX IF NOT EXISTS
          customer_hunt_products_user_active_idx
        ON customer_hunt_products (
          user_id,
          is_active,
          created_at DESC
        );

        CREATE TABLE IF NOT EXISTS customer_hunt_subscriptions (
          user_id TEXT PRIMARY KEY,

          plan VARCHAR(20) NOT NULL DEFAULT 'free',

          status VARCHAR(40) NOT NULL DEFAULT 'active',

          getly_subscription_id TEXT UNIQUE,

          current_period_end TIMESTAMPTZ,

          cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,

          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

          CONSTRAINT customer_hunt_subscription_plan_check
            CHECK (plan IN ('free', 'pro'))
        );

        CREATE TABLE IF NOT EXISTS customer_hunt_leads (
          id UUID PRIMARY KEY,

          product_id UUID NOT NULL,

          user_id TEXT NOT NULL,

          title VARCHAR(300) NOT NULL,

          excerpt TEXT NOT NULL DEFAULT '',

          source_url TEXT NOT NULL,

          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

          is_read BOOLEAN NOT NULL DEFAULT FALSE,

          CONSTRAINT customer_hunt_lead_source_check
            CHECK (source_url ~ '^https?://'),

          CONSTRAINT customer_hunt_lead_product_source_unique
            UNIQUE (product_id, source_url)
        );

        CREATE INDEX IF NOT EXISTS
          customer_hunt_leads_product_created_idx
        ON customer_hunt_leads (
          product_id,
          created_at DESC
        );

        CREATE INDEX IF NOT EXISTS
          customer_hunt_leads_user_unread_idx
        ON customer_hunt_leads (
          user_id,
          product_id,
          is_read
        );
      `);
    })().catch(error => {
      schemaPromise = null;
      throw error;
    });
  }

  return schemaPromise;
}

/**
 * Send a JSON response.
 */
function sendJson(res, statusCode, payload) {
  res.statusCode = statusCode;

  res.setHeader(
    "Content-Type",
    "application/json; charset=utf-8"
  );

  res.setHeader(
    "Cache-Control",
    "private, no-store, no-cache, must-revalidate"
  );

  res.setHeader("Pragma", "no-cache");

  res.end(JSON.stringify(payload));
}
/**
 * Parse a request body.
 */
function parseBody(req) {
  if (
    req.body &&
    typeof req.body === "object" &&
    !Array.isArray(req.body)
  ) {
    return req.body;
  }

  if (typeof req.body === "string") {
    try {
      const parsed = JSON.parse(req.body);

      if (
        parsed &&
        typeof parsed === "object" &&
        !Array.isArray(parsed)
      ) {
        return parsed;
      }
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Validate product name.
 */
function normalizeProductName(value) {
  if (typeof value !== "string") {
    return null;
  }

  const name = value.trim();

  if (name.length < 2 || name.length > 120) {
    return null;
  }

  if (/[\u0000-\u001F\u007F]/.test(name)) {
    return null;
  }

  return name;
}

/**
 * Validate target country/location.
 *
 * Accepts a country name or country label.
 * Does not silently replace the seller's input.
 */
function normalizeTargetLocation(value) {
  if (typeof value !== "string") {
    return null;
  }

  const location = value.trim();

  if (location.length < 2 || location.length > 100) {
    return null;
  }

  if (/[\u0000-\u001F\u007F]/.test(location)) {
    return null;
  }

  if (/^(https?:\/\/|www\.)/i.test(location)) {
    return null;
  }

  return location;
}

/**
 * Authenticate the current request.
 */
async function getAuthenticatedUser(auth, req) {
  const session = await auth.api.getSession({
    headers: convertHeaders(req.headers)
  });

  if (!session || !session.user || !session.user.id) {
    return null;
  }

  return session.user;
}

/**
 * Verify the request origin.
 *
 * POST requests must originate from the application
 * or provide same-origin Fetch Metadata when Origin
 * is unavailable.
 */
function verifyRequestOrigin(req, config) {
  const origin = req.headers.origin;

  if (origin) {
    if (origin === "null") {
      return false;
    }

    let parsedOrigin;

    try {
      const parsed = new URL(origin);

      if (
        parsed.username ||
        parsed.password ||
        parsed.pathname !== "/" ||
        parsed.search ||
        parsed.hash
      ) {
        return false;
      }

      parsedOrigin = parsed.origin;
    } catch {
      return false;
    }

    return config.trustedOrigins.includes(parsedOrigin);
  }

  return req.headers["sec-fetch-site"] === "same-origin";
}

/**
 * Determine whether a Pro subscription currently
 * grants access.
 *
 * Active subscriptions retain access.
 * Past-due subscriptions retain access only until
 * their current paid period ends.
 * Scheduled cancellations retain access until
 * their current period ends.
 */
function hasProAccess(subscription) {
  if (
    !subscription ||
    subscription.plan !== "pro"
  ) {
    return false;
  }

  const status = String(subscription.status || "").toLowerCase();

  if (status === "active") {
    if (subscription.cancel_at_period_end === true) {
      if (!subscription.current_period_end) {
        return false;
      }

      return new Date(subscription.current_period_end).getTime() > Date.now();
    }

    return true;
  }

  if (status === "past_due") {
    if (!subscription.current_period_end) {
      return false;
    }

    return new Date(subscription.current_period_end).getTime() > Date.now();
  }

  return false;
}

/**
 * Determine the user's current product allowance.
 *
 * Free: 1 active product.
 * Pro: 10 active products.
 */
async function getProductLimit(pool, userId) {
  const result = await pool.query(
    `
      SELECT
        plan,
        status,
        current_period_end,
        cancel_at_period_end
      FROM customer_hunt_subscriptions
      WHERE user_id = $1
      LIMIT 1
    `,
    [userId]
  );

  const subscription = result.rows[0] || null;
  const isPro = hasProAccess(subscription);

  return {
    plan: isPro ? "pro" : "free",
    productLimit: isPro ? 10 : 1
  };
}

/**
 * GET /api/create-product
 *
 * Returns the authenticated user's active products.
 */
async function listProducts(pool, user) {
  const result = await pool.query(
    `
      SELECT
        p.id,
        p.name,
        p.target_location AS "targetLocation",

        COUNT(l.id) FILTER (
          WHERE
            l.is_read = FALSE
            AND (
              p.last_opened_at IS NULL
              OR l.created_at > p.last_opened_at
            )
        )::INTEGER AS "unreadCount"

      FROM customer_hunt_products p

      LEFT JOIN customer_hunt_leads l
        ON l.product_id = p.id
        AND l.user_id = p.user_id

      WHERE
        p.user_id = $1
        AND p.is_active = TRUE

      GROUP BY
        p.id,
        p.name,
        p.target_location,
        p.created_at,
        p.last_opened_at

      ORDER BY p.created_at DESC
    `,
    [user.id]
  );

  const allowance = await getProductLimit(pool, user.id);

  return {
    success: true,

    products: result.rows.map(product => ({
      id: product.id,
      name: product.name,
      targetLocation: product.targetLocation,
      unreadCount: Number(product.unreadCount || 0)
    })),

    userName: user.name || "",

    plan: {
      name: allowance.plan,
      productLimit: allowance.productLimit
    },

    productsUsed: result.rowCount
  };
}
/**
 * POST /api/create-product
 *
 * Creates one product for the authenticated user.
 */
async function createProduct(pool, user, body) {
  const name = normalizeProductName(body.name);

  const targetLocation = normalizeTargetLocation(
    body.targetLocation
  );

  if (!name) {
    return {
      status: 400,
      payload: {
        success: false,
        error: "Enter a valid product name."
      }
    };
  }

  if (!targetLocation) {
    return {
      status: 400,
      payload: {
        success: false,
        error: "Enter a valid target country."
      }
    };
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    /**
     * Serialize product creation for this account.
     *
     * This prevents concurrent requests from exceeding
     * the account's active product allowance.
     */
    await client.query(
      `
        SELECT pg_advisory_xact_lock(
          hashtextextended($1, 0)
        )
      `,
      [user.id]
    );

    const subscriptionResult = await client.query(
      `
        SELECT
          plan,
          status,
          current_period_end,
          cancel_at_period_end
        FROM customer_hunt_subscriptions
        WHERE user_id = $1
        LIMIT 1
      `,
      [user.id]
    );

    const subscription = subscriptionResult.rows[0] || null;

    const isPro = hasProAccess(subscription);

    const productLimit = isPro ? 10 : 1;

    const countResult = await client.query(
      `
        SELECT COUNT(*)::INTEGER AS total
        FROM customer_hunt_products
        WHERE
          user_id = $1
          AND is_active = TRUE
      `,
      [user.id]
    );

    const productsUsed = Number(countResult.rows[0].total);

    if (productsUsed >= productLimit) {
      await client.query("ROLLBACK");

      return {
        status: 403,
        payload: {
          success: false,

          code: "product_limit_reached",

          error: isPro
            ? "You have reached your Pro product limit."
            : "Your Free plan allows one active product. Upgrade to Pro to create up to ten products.",

          plan: isPro ? "pro" : "free",

          productLimit,

          productsUsed,

          upgradeUrl: "/billing.html"
        }
      };
    }

    const productId = crypto.randomUUID();

    const insertResult = await client.query(
      `
        INSERT INTO customer_hunt_products (
          id,
          user_id,
          name,
          target_location,
          is_active
        )

        VALUES ($1, $2, $3, $4, TRUE)

        RETURNING
          id,
          name,
          target_location AS "targetLocation"
      `,
      [
        productId,
        user.id,
        name,
        targetLocation
      ]
    );

    await client.query("COMMIT");

    const product = insertResult.rows[0];

    return {
      status: 201,

      payload: {
        success: true,

        product: {
          id: product.id,
          name: product.name,
          targetLocation: product.targetLocation,
          unreadCount: 0
        }
      }
    };

  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // Preserve the original database error.
    }

    throw error;

  } finally {
    client.release();
  }
}

/**
 * Validate the incoming POST request format.
 */
function validatePostRequest(req) {
  const contentType = String(
    req.headers["content-type"] || ""
  ).toLowerCase();

  if (!contentType.startsWith("application/json")) {
    return {
      valid: false,
      status: 415,
      error: "A JSON request body is required."
    };
  }

  const contentLength = Number(req.headers["content-length"] || 0);

  if (
    Number.isFinite(contentLength) &&
    contentLength > 16384
  ) {
    return {
      valid: false,
      status: 413,
      error: "Request body is too large."
    };
  }

  return {
    valid: true
  };
}
/**
 * Main Vercel serverless handler.
 */
module.exports = async function createProductHandler(req, res) {
  res.setHeader("X-Content-Type-Options", "nosniff");

  res.setHeader("Referrer-Policy", "same-origin");

  res.setHeader("Cache-Control", "private, no-store");

  res.setHeader("Vary", "Cookie");

  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST");

    return sendJson(res, 405, {
      success: false,
      error: "Method not allowed."
    });
  }

  try {
    const application = await getApplication();

    const { auth, pool, config } = application;

    if (req.method === "POST") {
      const requestValidation = validatePostRequest(req);

      if (!requestValidation.valid) {
        return sendJson(
          res,
          requestValidation.status,
          {
            success: false,
            error: requestValidation.error
          }
        );
      }

      if (!verifyRequestOrigin(req, config)) {
        return sendJson(res, 403, {
          success: false,
          error: "Request origin is not permitted."
        });
      }
    }

    const user = await getAuthenticatedUser(auth, req);

    if (!user) {
      return sendJson(res, 401, {
        success: false,
        error: "Please sign in to continue.",
        redirect: "/signup.html"
      });
    }

    await ensureDatabaseSchema(pool);

    if (req.method === "GET") {
      const result = await listProducts(pool, user);

      return sendJson(res, 200, result);
    }

    const body = parseBody(req);

    if (!body) {
      return sendJson(res, 400, {
        success: false,
        error: "Invalid request body."
      });
    }

    const result = await createProduct(pool, user, body);

    return sendJson(res, result.status, result.payload);

  } catch (error) {
    const message = String(error?.message || "");

    if (
      message.includes("DATABASE_URL") ||
      message.includes("BETTER_AUTH_SECRET") ||
      message.includes("BETTER_AUTH_URL") ||
      message.includes("trusted application origin")
    ) {
      return sendJson(res, 500, {
        success: false,
        error: "Application configuration is incomplete."
      });
    }

    return sendJson(res, 500, {
      success: false,
      error: "We could not complete your product request. Please try again."
    });
  }
};