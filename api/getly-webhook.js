"use strict";

const crypto = require("crypto");
const { Pool } = require("pg");

const MAX_BODY_SIZE = 64 * 1024;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL &&
    !process.env.DATABASE_URL.includes("localhost")
      ? { rejectUnauthorized: false }
      : undefined,
  max: 5,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

let schemaReady = false;
let schemaPromise = null;

function send(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(payload));
}

function getHeader(req, name) {
  const value = req.headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value[0] || "";
  }

  return typeof value === "string" ? value : "";
}

function isValidSignature(rawBody, signature, secret) {
  if (
    typeof signature !== "string" ||
    typeof secret !== "string" ||
    !secret
  ) {
    return false;
  }

  const match = /^sha256=([a-f0-9]{64})$/i.exec(signature);

  if (!match) {
    return false;
  }

  const supplied = Buffer.from(match[1], "hex");

  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest();

  return (
    supplied.length === expected.length &&
    crypto.timingSafeEqual(supplied, expected)
  );
}

async function readRawBody(req) {
  const chunks = [];
  let totalSize = 0;

  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk)
      ? chunk
      : Buffer.from(chunk);

    totalSize += buffer.length;

    if (totalSize > MAX_BODY_SIZE) {
      const error = new Error("Webhook payload is too large.");
      error.statusCode = 413;
      throw error;
    }

    chunks.push(buffer);
  }

  return Buffer.concat(chunks);
}

function validDate(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }

  const date = new Date(value);

  return Number.isNaN(date.getTime()) ? null : date;
}

function getSubscriptionId(data) {
  const value =
    data.subscriptionId ||
    data.id ||
    data.subscription?.id;

  return typeof value === "string" && value.length <= 200
    ? value
    : null;
}
async function ensureSchema() {
  if (schemaReady) return;

  if (schemaPromise) {
    await schemaPromise;
    return;
  }

  schemaPromise = (async () => {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_hunt_subscriptions (
        user_id TEXT PRIMARY KEY,
        plan VARCHAR(20) NOT NULL DEFAULT 'free',
        status VARCHAR(40) NOT NULL DEFAULT 'inactive',
        getly_subscription_id TEXT,
        current_period_end TIMESTAMPTZ,
        cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_hunt_getly_webhook_events (
        delivery_id TEXT PRIMARY KEY,
        event_name VARCHAR(120) NOT NULL,
        processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS
      customer_hunt_getly_subscription_id_idx
      ON customer_hunt_subscriptions (getly_subscription_id)
    `);

    schemaReady = true;
  })();

  try {
    await schemaPromise;
  } finally {
    schemaPromise = null;
  }
}

function getCustomerReference(data) {
  const value =
    data.externalCustomerRef ||
    data.customerRef;

  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 200
  ) {
    return null;
  }

  return value;
}

function getPeriodEnd(data) {
  return (
    validDate(data.currentPeriodEnd) ||
    validDate(data.current_period_end) ||
    validDate(data.subscription?.currentPeriodEnd)
  );
}

function getCancellationFlag(data) {
  if (typeof data.cancelAtPeriodEnd === "boolean") {
    return data.cancelAtPeriodEnd;
  }

  if (typeof data.cancel_at_period_end === "boolean") {
    return data.cancel_at_period_end;
  }

  if (typeof data.subscription?.cancelAtPeriodEnd === "boolean") {
    return data.subscription.cancelAtPeriodEnd;
  }

  return false;
}

async function recordDelivery(client, deliveryId, eventName) {
  const result = await client.query(
    `
      INSERT INTO customer_hunt_getly_webhook_events (
        delivery_id,
        event_name
      )
      VALUES ($1, $2)
      ON CONFLICT (delivery_id) DO NOTHING
      RETURNING delivery_id
    `,
    [deliveryId, eventName]
  );

  return result.rowCount === 1;
}

async function updateSubscription(
  client,
  customerRef,
  subscriptionId,
  status,
  periodEnd,
  cancelAtPeriodEnd
) {
  await client.query(
    `
      INSERT INTO customer_hunt_subscriptions (
        user_id,
        plan,
        status,
        getly_subscription_id,
        current_period_end,
        cancel_at_period_end,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      ON CONFLICT (user_id)
      DO UPDATE SET
        plan = EXCLUDED.plan,
        status = EXCLUDED.status,
        getly_subscription_id = COALESCE(
          EXCLUDED.getly_subscription_id,
          customer_hunt_subscriptions.getly_subscription_id
        ),
        current_period_end = COALESCE(
          EXCLUDED.current_period_end,
          customer_hunt_subscriptions.current_period_end
        ),
        cancel_at_period_end = EXCLUDED.cancel_at_period_end,
        updated_at = NOW()
    `,
    [
      customerRef,
      status === "active" || status === "past_due" ? "pro" : "free",
      status,
      subscriptionId,
      periodEnd,
      cancelAtPeriodEnd
    ]
  );
}
async function processBillingEvent(client, eventName, data) {
  const customerRef = getCustomerReference(data);

  if (!customerRef) {
    throw new Error(
      "Getly billing event is missing externalCustomerRef."
    );
  }

  const subscriptionId = getSubscriptionId(data);
  const periodEnd = getPeriodEnd(data);
  const cancelAtPeriodEnd = getCancellationFlag(data);

  switch (eventName) {
    case "billing.subscription.created":
    case "billing.subscription.renewed": {
      await updateSubscription(
        client,
        customerRef,
        subscriptionId,
        "active",
        periodEnd,
        cancelAtPeriodEnd
      );

      return;
    }

    case "billing.payment_failed": {
      /*
       * Getly documents that past_due subscriptions remain entitled
       * until currentPeriodEnd. Preserve Pro access while that period
       * is still valid.
       */
      const stillEntitled =
        periodEnd !== null &&
        periodEnd.getTime() > Date.now();

      await updateSubscription(
        client,
        customerRef,
        subscriptionId,
        stillEntitled ? "past_due" : "inactive",
        periodEnd,
        cancelAtPeriodEnd
      );

      return;
    }

    case "billing.subscription.canceled": {
      await updateSubscription(
        client,
        customerRef,
        subscriptionId,
        "canceled",
        periodEnd,
        true
      );

      return;
    }

    case "billing.subscription.expired": {
      await updateSubscription(
        client,
        customerRef,
        subscriptionId,
        "expired",
        periodEnd,
        true
      );

      return;
    }

    default:
      return;
  }
}

function extractEvent(body, headerEvent) {
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return null;
  }

  const eventName =
    typeof body.event === "string"
      ? body.event
      : headerEvent;

  if (
    !eventName ||
    (headerEvent && headerEvent !== eventName)
  ) {
    return null;
  }

  const data =
    body.data && typeof body.data === "object"
      ? body.data
      : null;

  if (!data || Array.isArray(data)) {
    return null;
  }

  const deliveryId =
    typeof body.deliveryId === "string"
      ? body.deliveryId
      : null;

  if (
    !deliveryId ||
    deliveryId.length > 200
  ) {
    return null;
  }

  return {
    deliveryId,
    eventName,
    data
  };
}

async function handleWebhookEvent(event) {
  await ensureSchema();

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const isNewDelivery = await recordDelivery(
      client,
      event.deliveryId,
      event.eventName
    );

    if (!isNewDelivery) {
      await client.query("COMMIT");

      return {
        duplicate: true
      };
    }

    if (
      event.eventName.startsWith("billing.")
    ) {
      await processBillingEvent(
        client,
        event.eventName,
        event.data
      );
    }

    await client.query("COMMIT");

    return {
      duplicate: false
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");

    return send(res, 405, {
      success: false,
      error: "Method not allowed."
    });
  }

  const secret = process.env.GETLY_WEBHOOK_SECRET;

  if (!secret || !process.env.DATABASE_URL) {
    console.error(
      "Getly webhook configuration is incomplete."
    );

    return send(res, 500, {
      success: false,
      error: "Webhook service is not configured."
    });
  }

  let rawBody;

  try {
    rawBody = await readRawBody(req);
  } catch (error) {
    return send(
      res,
      error.statusCode || 400,
      {
        success: false,
        error: error.statusCode === 413
          ? "Webhook payload is too large."
          : "Unable to read webhook payload."
      }
    );
  }

  const signature = getHeader(
    req,
    "x-getly-signature"
  );

  if (!isValidSignature(rawBody, signature, secret)) {
    return send(res, 401, {
      success: false,
      error: "Invalid webhook signature."
    });
  }

  let body;

  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return send(res, 400, {
      success: false,
      error: "Invalid JSON payload."
    });
  }

  const headerEvent = getHeader(
    req,
    "x-getly-event"
  );

  const event = extractEvent(body, headerEvent);

  if (!event) {
    return send(res, 400, {
      success: false,
      error: "Invalid webhook event payload."
    });
  }

  try {
    const result = await handleWebhookEvent(event);

    return send(res, 200, {
      success: true,
      received: true,
      duplicate: result.duplicate
    });
  } catch (error) {
    console.error(
      "Getly webhook processing failed:",
      error.message
    );

    /*
     * A non-2xx response tells Getly to retry the delivery.
     * The database transaction ensures failed processing does
     * not permanently consume the delivery ID.
     */
    return send(res, 500, {
      success: false,
      error: "Webhook processing failed."
    });
  }
};

module.exports.config = {
  api: {
    bodyParser: false
  }
};
