// ============================================
// GoHighLevel (GHL) Marketplace App Integration
// ============================================
// 
// This module adds GHL OAuth and webhook routes to your existing Express app.
// It handles:
//   1. OAuth callback (token exchange when a user installs your app)
//   2. Token refresh (GHL tokens expire every ~24 hours)
//   3. GHL webhook receiver (reacts to events in the user's GHL account)
//   4. Media upload endpoint (watermark a file from GHL and upload it back)
//
// SETUP:
//   1. Add these env vars to your Render service:
//      - GHL_CLIENT_ID=69b458c10f3593c567044b68-mmp9kngg
//      - GHL_CLIENT_SECRET=fb9020ce-243a-4021-a396-ef5056b75b1c
//      - GHL_SHARED_SECRET=1ff632fa-88f1-43cf-8bc3-e02db3f88c54
//
//   2. Create a 'ghl_tokens' table in Supabase (SQL provided below)
//
//   3. In your index.js, add these two lines near the top:
//      const { mountGhlRoutes } = require('./ghl-integration');
//      mountGhlRoutes(app, supabase, logger);
//
// SUPABASE TABLE (run this in Supabase SQL Editor):
// 
//   CREATE TABLE ghl_tokens (
//     id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
//     location_id TEXT UNIQUE NOT NULL,
//     company_id TEXT,
//     access_token TEXT NOT NULL,
//     refresh_token TEXT NOT NULL,
//     token_type TEXT DEFAULT 'Bearer',
//     expires_at TIMESTAMPTZ NOT NULL,
//     scopes TEXT,
//     user_type TEXT DEFAULT 'Location',
//     installed_at TIMESTAMPTZ DEFAULT NOW(),
//     updated_at TIMESTAMPTZ DEFAULT NOW()
//   );
//
//   CREATE INDEX idx_ghl_tokens_location ON ghl_tokens(location_id);
//   CREATE INDEX idx_ghl_tokens_expires ON ghl_tokens(expires_at);
// ============================================

const crypto = require('crypto');
const fetch = require('node-fetch');

const GHL_API_BASE = 'https://services.leadconnectorhq.com';

// Environment variables
function getGhlConfig() {
  return {
    clientId: process.env.GHL_CLIENT_ID,
    clientSecret: process.env.GHL_CLIENT_SECRET,
    sharedSecret: process.env.GHL_SHARED_SECRET,
  };
}

// ============================================
// TOKEN MANAGEMENT
// ============================================

/**
 * Exchange authorization code for access + refresh tokens.
 * Called when a GHL user installs the app and gets redirected.
 */
async function exchangeCodeForToken(code) {
  const config = getGhlConfig();

  const response = await fetch(`${GHL_API_BASE}/oauth/token`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: 'authorization_code',
      code: code,
      user_type: 'Location',
    }).toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token exchange failed (${response.status}): ${errorText}`);
  }

  return await response.json();
}

/**
 * Refresh an expired access token using the refresh token.
 * GHL access tokens expire after ~24 hours.
 */
async function refreshAccessToken(refreshToken) {
  const config = getGhlConfig();

  const response = await fetch(`${GHL_API_BASE}/oauth/token`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      user_type: 'Location',
    }).toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token refresh failed (${response.status}): ${errorText}`);
  }

  return await response.json();
}

/**
 * Store tokens in Supabase (upsert by location_id).
 */
async function storeTokens(supabase, logger, tokenData, locationId, companyId) {
  const expiresAt = new Date(Date.now() + (tokenData.expires_in * 1000)).toISOString();

  const { error } = await supabase
    .from('ghl_tokens')
    .upsert({
      location_id: locationId,
      company_id: companyId || null,
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      token_type: tokenData.token_type || 'Bearer',
      expires_at: expiresAt,
      scopes: tokenData.scope || null,
      user_type: tokenData.userType || 'Location',
      updated_at: new Date().toISOString(),
    }, { onConflict: 'location_id' });

  if (error) {
    logger.error('Failed to store GHL tokens', { locationId, error: error.message });
    throw error;
  }

  logger.info('GHL tokens stored', { locationId, expiresAt });
}

/**
 * Get a valid access token for a location. Refreshes automatically if expired.
 */
async function getValidToken(supabase, logger, locationId) {
  const { data: tokenRow, error } = await supabase
    .from('ghl_tokens')
    .select('*')
    .eq('location_id', locationId)
    .single();

  if (error || !tokenRow) {
    throw new Error(`No GHL tokens found for location: ${locationId}`);
  }

  // Check if token is still valid (with 5 min buffer)
  const now = new Date();
  const expiresAt = new Date(tokenRow.expires_at);
  const bufferMs = 5 * 60 * 1000;

  if (now.getTime() < (expiresAt.getTime() - bufferMs)) {
    return tokenRow.access_token;
  }

  // Token expired or about to expire — refresh it
  logger.info('GHL token expired, refreshing', { locationId });

  const newTokenData = await refreshAccessToken(tokenRow.refresh_token);

  await storeTokens(supabase, logger, newTokenData, locationId, tokenRow.company_id);

  return newTokenData.access_token;
}

// ============================================
// GHL API HELPERS
// ============================================

/**
 * Download a media file from GHL by its media URL.
 */
async function downloadGhlMedia(accessToken, mediaUrl) {
  const response = await fetch(mediaUrl, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Version': '2021-07-28',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to download GHL media (${response.status})`);
  }

  return Buffer.from(await response.arrayBuffer());
}

/**
 * Upload a file to GHL media library.
 */
async function uploadToGhlMedia(accessToken, locationId, fileBuffer, filename) {
  const FormData = require('form-data');
  const form = new FormData();
  form.append('file', fileBuffer, { filename, contentType: 'application/pdf' });

  const response = await fetch(`${GHL_API_BASE}/medias/upload`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Version': '2021-07-28',
      ...form.getHeaders(),
    },
    body: form,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GHL media upload failed (${response.status}): ${errorText}`);
  }

  return await response.json();
}

/**
 * Get location details (used to get the company/user info after install).
 */
async function getLocationDetails(accessToken, locationId) {
  const response = await fetch(`${GHL_API_BASE}/locations/${locationId}`, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json',
      'Version': '2021-07-28',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to get location details (${response.status})`);
  }

  return await response.json();
}

// ============================================
// WEBHOOK SIGNATURE VERIFICATION
// ============================================

function verifyGhlWebhookSignature(payload, signature) {
  const config = getGhlConfig();
  const expected = crypto
    .createHmac('sha256', config.sharedSecret)
    .update(payload)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature || '', 'utf8'),
    Buffer.from(expected, 'utf8')
  );
}

// ============================================
// ROUTE HANDLERS
// ============================================

function mountGhlRoutes(app, supabase, logger) {
  
  // ------------------------------------------
  // OAuth Callback: Handles the redirect after 
  // a GHL user installs the app
  // ------------------------------------------
  app.get('/ghl/oauth/callback', async (req, res) => {
    try {
      const { code } = req.query;

      if (!code) {
        logger.warn('GHL OAuth callback missing code');
        return res.status(400).send('Missing authorization code');
      }

      logger.info('GHL OAuth callback received', { codePrefix: code.substring(0, 8) + '...' });

      // Exchange the code for tokens
      const tokenData = await exchangeCodeForToken(code);

      logger.info('GHL token exchange successful', {
        userType: tokenData.userType,
        locationId: tokenData.locationId,
        companyId: tokenData.companyId,
        scope: tokenData.scope,
      });

      // Store the tokens
      const locationId = tokenData.locationId;
      const companyId = tokenData.companyId;

      await storeTokens(supabase, logger, tokenData, locationId, companyId);

      // Return a success page
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Aquamark Connected</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f7f8fa; }
            .card { background: white; border-radius: 12px; padding: 48px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); max-width: 480px; }
            h1 { color: #1a1a2e; margin-bottom: 12px; }
            p { color: #666; line-height: 1.6; }
            .checkmark { font-size: 48px; margin-bottom: 16px; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="checkmark">&#10003;</div>
            <h1>Aquamark Connected</h1>
            <p>Your account has been successfully connected to Aquamark Watermarking. You can close this window and return to GoHighLevel.</p>
          </div>
        </body>
        </html>
      `);

    } catch (err) {
      logger.error('GHL OAuth callback error', { error: err.message });
      res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head><title>Connection Failed</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f7f8fa; }
            .card { background: white; border-radius: 12px; padding: 48px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); max-width: 480px; }
            h1 { color: #c0392b; }
            p { color: #666; line-height: 1.6; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>Connection Failed</h1>
            <p>Something went wrong connecting your account. Please try installing the app again, or contact support@aquamark.io for help.</p>
          </div>
        </body>
        </html>
      `);
    }
  });

  // ------------------------------------------
  // GHL Webhook Receiver: Handles events from 
  // GHL (app install/uninstall, etc.)
  // ------------------------------------------
  app.post('/ghl/webhook', async (req, res) => {
    try {
      // Always respond 200 quickly to avoid GHL retries
      res.status(200).json({ received: true });

      const event = req.body;
      
      logger.info('GHL webhook received', { 
        type: event.type, 
        appId: event.appId,
        locationId: event.locationId 
      });

      // Handle different event types
      switch (event.type) {
        case 'INSTALL':
          logger.info('GHL app installed', { 
            locationId: event.locationId, 
            companyId: event.companyId 
          });
          break;

        case 'UNINSTALL':
          logger.info('GHL app uninstalled', { locationId: event.locationId });
          // Clean up tokens for this location
          const { error: delError } = await supabase
            .from('ghl_tokens')
            .delete()
            .eq('location_id', event.locationId);
          
          if (delError) {
            logger.error('Failed to delete GHL tokens on uninstall', { error: delError.message });
          }
          break;

        default:
          logger.info('GHL webhook unhandled event type', { type: event.type });
      }

    } catch (err) {
      logger.error('GHL webhook processing error', { error: err.message });
    }
  });

  // ------------------------------------------
  // Watermark via GHL: Takes a GHL media URL,
  // watermarks it, and uploads back to GHL
  // ------------------------------------------
  app.post('/ghl/watermark', async (req, res) => {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing authorization' });
      }

      const token = authHeader.split(' ')[1];
      if (token !== process.env.AQUAMARK_API_KEY) {
        return res.status(401).json({ error: 'Invalid API key' });
      }

      const { location_id, media_url, filename } = req.body;

      if (!location_id || !media_url) {
        return res.status(400).json({ error: 'location_id and media_url are required' });
      }

      logger.info('GHL watermark request', { locationId: location_id, filename });

      // Get a valid GHL token for this location
      const ghlToken = await getValidToken(supabase, logger, location_id);

      // Download the file from GHL
      const fileBuffer = await downloadGhlMedia(ghlToken, media_url);

      // Return the file buffer info for now — the actual watermarking
      // will use your existing watermarkPdf function from index.js
      // This endpoint can be extended to call watermarkPdf directly

      res.json({
        success: true,
        message: 'GHL integration endpoint ready',
        location_id,
        file_size: fileBuffer.length,
        note: 'Watermarking pipeline will be connected in the next step',
      });

    } catch (err) {
      logger.error('GHL watermark error', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  // ------------------------------------------
  // Token Status: Check if a location has valid tokens
  // (useful for debugging)
  // ------------------------------------------
  app.get('/ghl/status/:locationId', async (req, res) => {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing authorization' });
      }

      const token = authHeader.split(' ')[1];
      if (token !== process.env.AQUAMARK_API_KEY) {
        return res.status(401).json({ error: 'Invalid API key' });
      }

      const { locationId } = req.params;

      const { data: tokenRow, error } = await supabase
        .from('ghl_tokens')
        .select('location_id, company_id, expires_at, scopes, user_type, installed_at, updated_at')
        .eq('location_id', locationId)
        .single();

      if (error || !tokenRow) {
        return res.status(404).json({ error: 'Location not connected', location_id: locationId });
      }

      const now = new Date();
      const expiresAt = new Date(tokenRow.expires_at);
      const isExpired = now >= expiresAt;

      res.json({
        location_id: tokenRow.location_id,
        company_id: tokenRow.company_id,
        connected: true,
        token_status: isExpired ? 'expired (will auto-refresh on next use)' : 'valid',
        expires_at: tokenRow.expires_at,
        scopes: tokenRow.scopes,
        installed_at: tokenRow.installed_at,
        updated_at: tokenRow.updated_at,
      });

    } catch (err) {
      logger.error('GHL status check error', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  // ------------------------------------------
  // List all connected GHL locations
  // ------------------------------------------
  app.get('/ghl/connections', async (req, res) => {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing authorization' });
      }

      const token = authHeader.split(' ')[1];
      if (token !== process.env.AQUAMARK_API_KEY) {
        return res.status(401).json({ error: 'Invalid API key' });
      }

      const { data: connections, error } = await supabase
        .from('ghl_tokens')
        .select('location_id, company_id, expires_at, installed_at, updated_at')
        .order('installed_at', { ascending: false });

      if (error) {
        throw error;
      }

      res.json({
        total: connections ? connections.length : 0,
        connections: connections || [],
      });

    } catch (err) {
      logger.error('GHL connections list error', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  logger.info('GHL integration routes mounted', {
    routes: [
      'GET  /ghl/oauth/callback',
      'POST /ghl/webhook',
      'POST /ghl/watermark',
      'GET  /ghl/status/:locationId',
      'GET  /ghl/connections',
    ]
  });
}

module.exports = { mountGhlRoutes, getValidToken, uploadToGhlMedia, downloadGhlMedia };
