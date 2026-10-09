const express = require("express");
const crypto = require("crypto");
const axios = require("axios");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SCOPES = process.env.SHOPIFY_SCOPES || "read_draft_orders,write_draft_orders,read_products,write_products,read_orders,write_orders,read_customers,write_customers,read_inventory,write_inventory,read_shipping,write_shipping,read_checkouts,write_checkouts,read_price_rules,write_price_rules,read_discounts,write_discounts,read_content,write_content";
const REDIRECT_URI = process.env.REDIRECT_URI || `http://localhost:${PORT}/auth/callback`;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("❌ Missing SHOPIFY_CLIENT_ID or SHOPIFY_CLIENT_SECRET in .env");
  process.exit(1);
}

// Step 1: Start install — redirect to Shopify OAuth
// Visit: http://localhost:3000/install?shop=your-store.myshopify.com
app.get("/install", (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send("Missing ?shop= param");

  const state = crypto.randomBytes(16).toString("hex");
  const authUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${CLIENT_ID}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&state=${state}`;

  console.log(`\n🔗 Redirecting to Shopify OAuth for shop: ${shop}`);
  res.redirect(authUrl);
});

// Step 2: Shopify redirects here with ?code=...
app.get("/auth/callback", async (req, res) => {
  const { shop, code, hmac, state } = req.query;

  if (!shop || !code) {
    return res.status(400).send("Missing shop or code");
  }

  // Verify HMAC signature from Shopify
  const params = { ...req.query };
  delete params.hmac;
  const message = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("&");
  const digest = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(message)
    .digest("hex");

  if (digest !== hmac) {
    console.error("❌ HMAC validation failed");
    return res.status(403).send("HMAC validation failed");
  }

  // Exchange code for access token
  try {
    const response = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
      }
    );

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

app.get("/", (req, res) => {
  res.send(`
    <h2>Shopify OAuth Token Tool</h2>
    <p>Visit <a href="/install?shop=printingneedle.myshopify.com">/install?shop=printingneedle.myshopify.com</a> to begin.</p>
  `);
});

app.listen(PORT, () => {
  console.log(`\n🚀 Server running at http://localhost:${PORT}`);
  console.log(`   Start install: http://localhost:${PORT}/install?shop=printingneedle.myshopify.com\n`);
});
