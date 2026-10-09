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

// shortcut: in-memory state store, lost on restart; use a cookie/session if many people install at once
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

function startAuth(req, res) {
  const shop = String(req.query.shop || "").trim().toLowerCase();
  if (!SHOP_RE.test(shop)) return res.status(400).send("Invalid or missing ?shop= (must be xxx.myshopify.com)");

  // Opened from Shopify admin → request is signed; reject if tampered
  if (req.query.hmac && !verifyHmac(req.query)) return res.status(403).send("HMAC validation failed");

  const state = crypto.randomBytes(16).toString("hex");
  pendingStates.set(state, shop);

  const authUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${CLIENT_ID}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&state=${state}`;

  console.log(`\n🔗 Redirecting to Shopify OAuth for shop: ${shop}`);

  // Embedded app inside admin iframe: OAuth page can't load in an iframe, so break out to top window
  if (req.query.embedded === "1") {
    return res.send(`<!DOCTYPE html><html><head>
<meta name="shopify-api-key" content="${CLIENT_ID}">
<script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
</head><body><script>open(${JSON.stringify(authUrl)}, "_top");</script></body></html>`);
  }
  res.redirect(authUrl);
}

// Opened from store admin (Shopify sends ?shop=&hmac=&host=...) OR manually with ?shop=
app.get("/", (req, res) => {
  if (req.query.shop) return startAuth(req, res);
  res.send(`
    <h2>Shopify OAuth Token Tool</h2>
    <form action="/install">
      <input name="shop" placeholder="your-store.myshopify.com" required>
      <button>Install</button>
    </form>
  `);
});

// Old link still works: /install?shop=your-store.myshopify.com
app.get("/install", startAuth);

app.get("/auth/callback", async (req, res) => {
  const { shop, code, state } = req.query;

  if (!shop || !code || !SHOP_RE.test(shop)) return res.status(400).send("Missing or invalid shop/code");
  if (!verifyHmac(req.query)) {
    console.error("❌ HMAC validation failed");
    return res.status(403).send("HMAC validation failed");
  }
  if (pendingStates.get(state) !== shop) return res.status(403).send("Invalid state — start install again");
  pendingStates.delete(state);

  try {
    const response = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
    });

    const accessToken = response.data.access_token;
    const scope = response.data.scope;

    console.log("\n✅ Access Token received!");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log(`   Shop:         ${shop}`);
    console.log(`   Access Token: ${accessToken}`);
    console.log(`   Scopes:       ${scope}`);
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    res.send(`
      <h2>✅ Installation Complete</h2>
      <p><strong>Shop:</strong> ${shop}</p>
      <p><strong>Access Token:</strong> <code>${accessToken}</code></p>
      <p><strong>Scopes:</strong> ${scope}</p>
      <p>Token has been logged to your console.</p>
    `);
  } catch (err) {
    const msg = err.response?.data || err.message;
    console.error("❌ Token exchange failed:", msg);
    res.status(500).send("Token exchange failed: " + JSON.stringify(msg));
  }
});

app.listen(PORT, () => {
  console.log(`\n🚀 Server running on port ${PORT}`);
  console.log(`   App URL:       ${APP_URL}`);
  console.log(`   Redirect URI:  ${REDIRECT_URI}`);
  console.log(`   Start install: ${APP_URL}/?shop=your-store.myshopify.com\n`);
});