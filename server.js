const express = require("express");
const crypto = require("crypto");
const axios = require("axios");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SCOPES = process.env.SHOPIFY_SCOPES || "read_draft_orders,write_draft_orders,read_products,write_products,read_orders,write_orders,read_customers,write_customers,read_inventory,write_inventory,read_shipping,write_shipping,read_checkouts,write_checkouts,read_price_rules,write_price_rules,read_discounts,write_discounts,read_content,write_content";
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
const REDIRECT_URI = process.env.REDIRECT_URI || `${APP_URL}/auth/callback`;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("❌ Missing SHOPIFY_CLIENT_ID or SHOPIFY_CLIENT_SECRET in .env");
  process.exit(1);
}

// Only real *.myshopify.com domains — blocks open redirects and leaking CLIENT_SECRET to other hosts
const SHOP_RE = /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i;

// shortcut: in-memory state store, breaks on serverless (Vercel) across instances; only used by the manual OAuth fallback
const pendingStates = new Map(); // state -> shop

function verifyHmac(query) {
  const { hmac, ...params } = query;
  if (!hmac) return false;
  const message = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("&");
  const digest = crypto.createHmac("sha256", CLIENT_SECRET).update(message).digest("hex");
  const a = Buffer.from(digest);
  const b = Buffer.from(String(hmac));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function showToken(res, shop, accessToken, scope) {
  console.log("\n✅ Access Token received!");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`   Shop:         ${shop}`);
  console.log(`   Access Token: ${accessToken}`);
  console.log(`   Scopes:       ${scope}`);
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

  res.send(`
    <h2>✅ Access Token</h2>
    <p><strong>Shop:</strong> ${shop}</p>
    <p><strong>Access Token:</strong> <code>${accessToken}</code></p>
    <p><strong>Scopes:</strong> ${scope}</p>
  `);
}

function sendError(res, label, err) {
  const msg = err.response?.data || err.message;
  console.error(`❌ ${label}:`, msg);
  res.status(500).send(`${label}: ` + JSON.stringify(msg));
}

// Opened from admin (embedded, Shopify-managed install): swap the session token for an offline token. No redirect needed.
async function tokenExchange(req, res) {
  const shop = String(req.query.shop).toLowerCase();
  if (!SHOP_RE.test(shop)) return res.status(400).send("Invalid shop");
  if (!verifyHmac(req.query)) return res.status(403).send("HMAC validation failed");

  try {
    const { data } = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: req.query.id_token,
      subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
      requested_token_type: "urn:shopify:params:oauth:token-type:offline-access-token",
    });
    showToken(res, shop, data.access_token, data.scope);
  } catch (err) {
    sendError(res, "Token exchange failed", err);
  }
}

// Manual fallback: classic OAuth redirect (needs APP_URL set correctly)
function startAuth(req, res) {
  const shop = String(req.query.shop || "").trim().toLowerCase();
  if (!SHOP_RE.test(shop)) return res.status(400).send("Invalid or missing ?shop= (must be xxx.myshopify.com)");
  if (req.query.hmac && !verifyHmac(req.query)) return res.status(403).send("HMAC validation failed");

  const state = crypto.randomBytes(16).toString("hex");
  pendingStates.set(state, shop);

  const authUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${CLIENT_ID}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&state=${state}`;

  console.log(`\n🔗 OAuth for ${shop}, redirect_uri=${REDIRECT_URI}`);

  if (req.query.embedded === "1") {
    return res.send(`<!DOCTYPE html><html><head>
<meta name="shopify-api-key" content="${CLIENT_ID}">
<script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
</head><body><script>open(${JSON.stringify(authUrl)}, "_top");</script></body></html>`);
  }
  res.redirect(authUrl);
}

app.get("/", (req, res) => {
  if (req.query.shop && req.query.id_token) return tokenExchange(req, res);
  if (req.query.shop) return startAuth(req, res);
  res.send(`
    <h2>Shopify OAuth Token Tool</h2>
    <form action="/install">
      <input name="shop" placeholder="your-store.myshopify.com" required>
      <button>Install</button>
    </form>
  `);
});

app.get("/install", startAuth);

app.get("/auth/callback", async (req, res) => {
  const { shop, code, state } = req.query;

  if (!shop || !code || !SHOP_RE.test(shop)) return res.status(400).send("Missing or invalid shop/code");
  if (!verifyHmac(req.query)) return res.status(403).send("HMAC validation failed");
  if (pendingStates.get(state) !== shop) return res.status(403).send("Invalid state — start install again");
  pendingStates.delete(state);

  try {
    const { data } = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
    });
    showToken(res, shop, data.access_token, data.scope);
  } catch (err) {
    sendError(res, "Token exchange failed", err);
  }
});

app.listen(PORT, () => {
  console.log(`\n🚀 Server running on port ${PORT}`);
  console.log(`   App URL:       ${APP_URL}`);
  console.log(`   Redirect URI:  ${REDIRECT_URI}`);
  console.log(`   Start install: ${APP_URL}/?shop=your-store.myshopify.com\n`);
});