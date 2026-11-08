"use strict";

/**
 * CUSTOMER HUNT
 * Lead Inbox API
 *
 * Runtime: Vercel Node.js
 * Database: Layerbase PostgreSQL
 * Authentication: Better Auth
 *
 * Supported methods:
 *
 * GET:
 * /api/get-leads?productId=PRODUCT_ID
 *
 * POST:
 * { action: "open-product", productId: "..." }
 *
 * { action: "mark-read", productId: "...", leadId: "..." }
 */

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
      throw new Error(
        "Application origins must contain only an origin."
      );
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
 * Initialize PostgreSQL and Better Auth.
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
    // Database errors are not exposed to clients.
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
 * Ensure the inbox supports product opening timestamps.
 *
 * Individual lead read states remain independent.
 */
async function ensureDatabaseSchema(pool) {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await pool.query(`
        ALTER TABLE customer_hunt_products
          ADD COLUMN IF NOT EXISTS last_opened_at TIMESTAMPTZ;

        CREATE INDEX IF NOT EXISTS
          customer_hunt_leads_product_read_created_idx
        ON customer_hunt_leads (
          product_id,
          is_read,
          created_at DESC
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
 * Send JSON safely.
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
 * Parse JSON request body.
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
 * Validate request body format and size.
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

  const contentLength = Number(
    req.headers["content-length"] || 0
  );

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

  if (req.body && typeof req.body === "object") {
    try {
      if (
        Buffer.byteLength(JSON.stringify(req.body), "utf8") >
        16384
      ) {
        return {
          valid: false,
          status: 413,
          error: "Request body is too large."
        };
      }
    } catch {
      return {
        valid: false,
        status: 400,
        error: "Invalid request body."
      };
    }
  }

  return {
    valid: true
  };
}

/**
 * Validate UUID identifiers.
 */
function isValidUUID(value) {
  if (typeof value !== "string") {
    return false;
  }

  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value
  );
}

/**
 * Authenticate the current user.
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
 * Confirm that the product belongs to the signed-in user.
 */
async function verifyProductOwnership(pool, productId, userId) {
  const result = await pool.query(
    `
      SELECT
        id,
        name,
        target_location AS "targetLocation",
        last_opened_at AS "lastOpenedAt"

      FROM customer_hunt_products

      WHERE
        id = $1
        AND user_id = $2
        AND is_active = TRUE

      LIMIT 1
    `,
    [productId, userId]
  );

  return result.rows[0] || null;
}

/**
 * Validate and normalize a lead source URL.
 */
function normalizeSourceUrl(value) {
  if (typeof value !== "string" || value.length > 4096) {
    return null;
  }

  try {
    const url = new URL(value);

    if (!["http:", "https:"].includes(url.protocol)) {
      return null;
    }

    if (url.username || url.password) {
      return null;
    }

    return url.href;

  } catch {
    return null;
  }
}

/**
 * Count unread leads that arrived after the product
 * was last opened.
 *
 * This is the product-level badge count.
 *
 * Individual unread lead states are not changed.
 */
async function getProductUnreadCount(
  pool,
  productId,
  userId,
  lastOpenedAt
) {
  const result = await pool.query(
    `
      SELECT COUNT(*)::INTEGER AS total

      FROM customer_hunt_leads

      WHERE
        product_id = $1
        AND user_id = $2
        AND is_read = FALSE
        AND (
          $3::TIMESTAMPTZ IS NULL
          OR created_at > $3::TIMESTAMPTZ
        )
    `,
    [
      productId,
      userId,
      lastOpenedAt
    ]
  );

  return Number(result.rows[0]?.total || 0);
}
/**
 * GET /api/get-leads?productId=...
 *
 * Returns leads belonging to the authenticated user
 * and the requested product.
 */
async function getProductLeads(pool, productId, user) {
  if (!isValidUUID(productId)) {
    return {
      status: 400,
      payload: {
        success: false,
        error: "Invalid product identifier."
      }
    };
  }

  const product = await verifyProductOwnership(
    pool,
    productId,
    user.id
  );

  if (!product) {
    return {
      status: 404,
      payload: {
        success: false,
        error: "Product not found."
      }
    };
  }

  const result = await pool.query(
    `
      SELECT
        id,
        title,
        excerpt,
        source_url AS "sourceUrl",
        created_at AS "createdAt",
        is_read AS "isRead"

      FROM customer_hunt_leads

      WHERE
        product_id = $1
        AND user_id = $2

      ORDER BY
        created_at DESC,
        id DESC

      LIMIT 500
    `,
    [
      productId,
      user.id
    ]
  );

  const unreadCount = await getProductUnreadCount(
    pool,
    productId,
    user.id,
    product.lastOpenedAt
  );

  return {
    status: 200,

    payload: {
      success: true,

      product: {
        id: product.id,
        name: product.name,
        targetLocation: product.targetLocation,
        unreadCount
      },

      leads: result.rows.map(lead => ({
        id: lead.id,
        title: lead.title,
        excerpt: lead.excerpt,
        sourceUrl: normalizeSourceUrl(lead.sourceUrl),
        createdAt: lead.createdAt,
        isRead: lead.isRead
      }))
    }
  };
}

/**
 * POST action: open-product
 *
 * Records when the user opens a product inbox.
 *
 * Clears the product-level unread badge for leads
 * received up to the opening timestamp.
 *
 * Does not automatically mark individual leads read.
 */
async function openProduct(pool, productId, user) {
  if (!isValidUUID(productId)) {
    return {
      status: 400,
      payload: {
        success: false,
        error: "Invalid product identifier."
      }
    };
  }

  const result = await pool.query(
    `
      UPDATE customer_hunt_products

      SET
        last_opened_at = clock_timestamp(),
        updated_at = NOW()

      WHERE
        id = $1
        AND user_id = $2
        AND is_active = TRUE

      RETURNING
        id,
        last_opened_at AS "lastOpenedAt"
    `,
    [
      productId,
      user.id
    ]
  );

  if (result.rowCount === 0) {
    return {
      status: 404,
      payload: {
        success: false,
        error: "Product not found."
      }
    };
  }

  return {
    status: 200,

    payload: {
      success: true,
      message: "Product inbox opened."
    }
  };
}

/**
 * POST action: mark-read
 *
 * Marks only the selected lead as read.
 */
async function markLeadRead(pool, productId, leadId, user) {
  if (!isValidUUID(productId) || !isValidUUID(leadId)) {
    return {
      status: 400,
      payload: {
        success: false,
        error: "Invalid product or lead identifier."
      }
    };
  }

  const product = await verifyProductOwnership(
    pool,
    productId,
    user.id
  );

  if (!product) {
    return {
      status: 404,
      payload: {
        success: false,
        error: "Product not found."
      }
    };
  }

  const result = await pool.query(
    `
      UPDATE customer_hunt_leads

      SET is_read = TRUE

      WHERE
        id = $1
        AND product_id = $2
        AND user_id = $3

      RETURNING
        id,
        is_read AS "isRead"
    `,
    [
      leadId,
      productId,
      user.id
    ]
  );

  if (result.rowCount === 0) {
    return {
      status: 404,
      payload: {
        success: false,
        error: "Lead not found."
      }
    };
  }

  const unreadCount = await getProductUnreadCount(
    pool,
    productId,
    user.id,
    product.lastOpenedAt
  );

  return {
    status: 200,

    payload: {
      success: true,

      lead: {
        id: result.rows[0].id,
        isRead: true
      },

      unreadCount
    }
  };
}
/**
 * Verify browser request origin for POST requests.
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
 * Main Vercel serverless handler.
 */
module.exports = async function getLeadsHandler(req, res) {
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
      const validation = validatePostRequest(req);

      if (!validation.valid) {
        return sendJson(
          res,
          validation.status,
          {
            success: false,
            error: validation.error
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
      const productId = req.query?.productId;

      const result = await getProductLeads(
        pool,
        productId,
        user
      );

      return sendJson(
        res,
        result.status,
        result.payload
      );
    }

    const body = parseBody(req);

    if (!body) {
      return sendJson(res, 400, {
        success: false,
        error: "Invalid request body."
      });
    }

    const productId = body.productId;

    let result;

    switch (body.action) {
      case "open-product":
        result = await openProduct(
          pool,
          productId,
          user
        );
        break;

      case "mark-read":
        result = await markLeadRead(
          pool,
          productId,
          body.leadId,
          user
        );
        break;

      default:
        return sendJson(res, 400, {
          success: false,
          error: "Invalid lead action."
        });
    }

    return sendJson(
      res,
      result.status,
      result.payload
    );

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
      error: "We could not load your leads. Please try again."
    });
  }
};