// ============================================
// GoHighLevel (GHL) Marketplace App Integration
// ============================================
//
// v2: Includes OAuth, Custom Page with SSO, logo upload, and watermarking.
//
// SETUP:
//   1. Env vars on Render:
//      - GHL_CLIENT_ID
//      - GHL_CLIENT_SECRET
//      - GHL_SHARED_SECRET
//
//   2. In your index.js, mount with:
//      const { mountGhlRoutes } = require('./ghl-integration');
//      mountGhlRoutes(app, supabase, logger, { watermarkPdf, getCachedLogo });
//
//   3. npm install crypto-js multer
//
//   4. Add user_email column to ghl_tokens:
//      ALTER TABLE ghl_tokens ADD COLUMN IF NOT EXISTS user_email TEXT;
//
//   5. Set Custom Page URL in GHL Marketplace app (Modules > Custom Page):
//      https://broker-standard-api-new.onrender.com/ghl/app
// ============================================

const crypto = require('crypto');
const fetch = require('node-fetch');
const CryptoJS = require('crypto-js');

const GHL_API_BASE = 'https://services.leadconnectorhq.com';

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

async function exchangeCodeForToken(code) {
  const config = getGhlConfig();
  const response = await fetch(`${GHL_API_BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: 'authorization_code',
      code,
      user_type: 'Location',
    }).toString(),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token exchange failed (${response.status}): ${errorText}`);
  }
  return await response.json();
}

async function refreshAccessToken(refreshToken) {
  const config = getGhlConfig();
  const response = await fetch(`${GHL_API_BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
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

async function getValidToken(supabase, logger, locationId) {
  const { data: tokenRow, error } = await supabase
    .from('ghl_tokens')
    .select('*')
    .eq('location_id', locationId)
    .single();
  if (error || !tokenRow) throw new Error(`No GHL tokens found for location: ${locationId}`);

  const bufferMs = 5 * 60 * 1000;
  if (Date.now() < (new Date(tokenRow.expires_at).getTime() - bufferMs)) {
    return tokenRow.access_token;
  }

  logger.info('GHL token expired, refreshing', { locationId });
  const newTokenData = await refreshAccessToken(tokenRow.refresh_token);
  await storeTokens(supabase, logger, newTokenData, locationId, tokenRow.company_id);
  return newTokenData.access_token;
}

// ============================================
// SSO DECRYPTION
// ============================================

function decryptSsoData(encryptedData) {
  const config = getGhlConfig();
  const decrypted = CryptoJS.AES.decrypt(encryptedData, config.sharedSecret);
  const jsonStr = decrypted.toString(CryptoJS.enc.Utf8);
  if (!jsonStr) throw new Error('SSO decryption produced empty result');
  return JSON.parse(jsonStr);
}

// ============================================
// GHL API HELPERS
// ============================================

async function listGhlMedia(accessToken) {
  const params = new URLSearchParams({ offset: '0', limit: '100', sortBy: 'createdAt', sortOrder: 'desc' });
  const response = await fetch(`${GHL_API_BASE}/medias/files?${params.toString()}`, {
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Version': '2021-07-28', 'Accept': 'application/json' },
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to list GHL media (${response.status}): ${errorText}`);
  }
  return await response.json();
}

async function downloadGhlMedia(accessToken, mediaUrl) {
  const response = await fetch(mediaUrl, {
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Version': '2021-07-28' },
  });
  if (!response.ok) throw new Error(`Failed to download GHL media (${response.status})`);
  return Buffer.from(await response.arrayBuffer());
}

async function uploadToGhlMedia(accessToken, fileBuffer, filename) {
  const FormData = require('form-data');
  const form = new FormData();
  form.append('file', fileBuffer, { filename, contentType: 'application/pdf' });
  form.append('hosted', 'false');
  form.append('name', filename);
  const response = await fetch(`${GHL_API_BASE}/medias/upload`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Version': '2021-07-28', ...form.getHeaders() },
    body: form,
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GHL media upload failed (${response.status}): ${errorText}`);
  }
  return await response.json();
}

// ============================================
// USER PROVISIONING
// ============================================

async function ensureAquamarkUser(supabase, logger, email) {
  const { data: existing } = await supabase.from('users').select('id, email, plan').eq('email', email).single();
  if (existing) return existing;

  const { data: newUser, error } = await supabase
    .from('users')
    .insert({ email, plan: 'Standard', created_at: new Date().toISOString() })
    .select()
    .single();
  if (error) {
    logger.error('Failed to create Aquamark user', { email, error: error.message });
    throw error;
  }
  logger.info('Created Aquamark user from GHL install', { email, plan: 'Standard' });
  return newUser;
}

async function checkLogoExists(supabase, email) {
  const { data: logoList } = await supabase.storage.from('logos').list(email);
  if (!logoList || logoList.length === 0) return false;
  const actualLogos = logoList.filter(file =>
    !file.name.includes('emptyFolderPlaceholder') &&
    !file.name.includes('.emptyFolderPlaceholder') &&
    (file.name.includes('logo-') || file.name.endsWith('.png') || file.name.endsWith('.jpg'))
  );
  return actualLogos.length > 0;
}

async function uploadLogo(supabase, logger, email, fileBuffer, originalName) {
  const ext = originalName.split('.').pop() || 'png';
  const filename = `logo-${Date.now()}.${ext}`;
  const storagePath = `${email}/${filename}`;
  const { error } = await supabase.storage
    .from('logos')
    .upload(storagePath, fileBuffer, {
      contentType: ext === 'jpg' || ext === 'jpeg' ? 'image/jpeg' : 'image/png',
      upsert: true,
    });
  if (error) {
    logger.error('Logo upload failed', { email, error: error.message });
    throw error;
  }
  logger.info('Logo uploaded for GHL user', { email, storagePath });
  return storagePath;
}

// ============================================
// CUSTOM PAGE HTML
// ============================================

function getCustomPageHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Aquamark Watermarking</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;color:#1a1a2e;padding:24px}
    .container{max-width:800px;margin:0 auto}
    .header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #e5e7eb}
    .header h1{font-size:20px;font-weight:600}
    .status-bar{border-radius:8px;padding:12px 16px;margin-bottom:20px;font-size:14px;display:none}
    .status-bar.visible{display:block}
    .status-bar.success{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534}
    .status-bar.error{background:#fef2f2;border:1px solid #fecaca;color:#991b1b}
    .status-bar.info{background:#eff6ff;border:1px solid #bfdbfe;color:#1e40af}
    .setup-section{background:white;border-radius:12px;padding:40px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.06)}
    .setup-section h2{font-size:18px;margin-bottom:8px}
    .setup-section p{color:#6b7280;margin-bottom:24px;font-size:14px;line-height:1.5}
    .upload-zone{border:2px dashed #d1d5db;border-radius:8px;padding:32px;cursor:pointer;transition:border-color .2s}
    .upload-zone:hover{border-color:#3b82f6}
    .upload-zone.dragover{border-color:#3b82f6;background:#eff6ff}
    .upload-zone input{display:none}
    .upload-zone .icon{font-size:32px;margin-bottom:8px}
    .upload-zone .label{color:#6b7280;font-size:14px}
    .upload-zone .label strong{color:#3b82f6}
    .logo-preview{max-width:200px;max-height:100px;margin:12px auto;display:none;border-radius:4px}
    .file-section{background:white;border-radius:12px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
    .toolbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
    .toolbar .count{font-size:13px;color:#6b7280}
    .btn{padding:8px 20px;border-radius:6px;font-size:14px;font-weight:500;cursor:pointer;border:none;transition:background .2s}
    .btn-primary{background:#3b82f6;color:white}
    .btn-primary:hover{background:#2563eb}
    .btn-primary:disabled{background:#93c5fd;cursor:not-allowed}
    .btn-secondary{background:#f3f4f6;color:#374151}
    .btn-secondary:hover{background:#e5e7eb}
    .btn-upload{background:#10b981;color:white;padding:10px 28px;font-size:15px;margin-top:16px}
    .btn-upload:hover{background:#059669}
    .select-all{display:flex;align-items:center;gap:8px;font-size:13px;color:#6b7280;padding:8px 0;border-bottom:1px solid #f3f4f6;margin-bottom:8px}
    .select-all input{width:16px;height:16px;cursor:pointer}
    .file-list{list-style:none;max-height:400px;overflow-y:auto}
    .file-item{display:flex;align-items:center;gap:12px;padding:10px 8px;border-bottom:1px solid #f9fafb;transition:background .15s}
    .file-item:hover{background:#f9fafb}
    .file-item input{width:16px;height:16px;cursor:pointer;flex-shrink:0}
    .file-item .file-icon{font-size:20px;flex-shrink:0}
    .file-item .file-info{flex:1;min-width:0}
    .file-item .file-name{font-size:14px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .file-item .file-meta{font-size:12px;color:#9ca3af;margin-top:2px}
    .empty-state{text-align:center;padding:48px 20px;color:#9ca3af}
    .empty-state .icon{font-size:40px;margin-bottom:12px}
    .empty-state p{font-size:14px}
    .loading{text-align:center;padding:40px;color:#6b7280}
    .spinner{display:inline-block;width:24px;height:24px;border:3px solid #e5e7eb;border-top-color:#3b82f6;border-radius:50%;animation:spin .8s linear infinite;margin-bottom:12px}
    @keyframes spin{to{transform:rotate(360deg)}}
    .progress-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:100;justify-content:center;align-items:center}
    .progress-overlay.visible{display:flex}
    .progress-card{background:white;border-radius:12px;padding:32px 40px;text-align:center;min-width:300px;box-shadow:0 8px 30px rgba(0,0,0,.15)}
    .progress-card .spinner{width:32px;height:32px}
    .progress-card h3{font-size:16px;margin:12px 0 4px}
    .progress-card p{font-size:13px;color:#6b7280}
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>Aquamark Watermarking</h1></div>
    <div id="statusBar" class="status-bar"></div>

    <div id="loadingState" class="loading">
      <div class="spinner"></div>
      <p>Connecting to your account...</p>
    </div>

    <div id="setupSection" class="setup-section" style="display:none">
      <h2>Upload Your Logo</h2>
      <p>Upload your company logo to get started. This will be used as your watermark on all documents. You only need to do this once.</p>
      <div class="upload-zone" id="uploadZone">
        <input type="file" id="logoInput" accept="image/png,image/jpeg,image/jpg">
        <div class="icon">&#128247;</div>
        <div class="label">Drag &amp; drop your logo here, or <strong>click to browse</strong></div>
        <div style="margin-top:8px;font-size:12px;color:#9ca3af">PNG or JPG, recommended 400x400px or larger</div>
      </div>
      <img id="logoPreview" class="logo-preview" alt="Logo preview">
      <br>
      <button id="uploadLogoBtn" class="btn btn-upload" style="display:none" onclick="submitLogo()">Save Logo &amp; Continue</button>
    </div>

    <div id="fileSection" class="file-section" style="display:none">
      <div class="toolbar">
        <span id="selectedCount" class="count">0 files selected</span>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" onclick="refreshFiles()">Refresh</button>
          <button id="watermarkBtn" class="btn btn-primary" disabled onclick="watermarkSelected()">Watermark Selected</button>
        </div>
      </div>
      <div class="select-all">
        <input type="checkbox" id="selectAllBox" onchange="toggleSelectAll()">
        <label for="selectAllBox">Select all</label>
      </div>
      <ul id="fileList" class="file-list"></ul>
    </div>
  </div>

  <div id="progressOverlay" class="progress-overlay">
    <div class="progress-card">
      <div class="spinner"></div>
      <h3 id="progressTitle">Watermarking...</h3>
      <p id="progressDetail">Processing file 1 of 3</p>
    </div>
  </div>

<script>
  let sessionData = null;
  let files = [];
  let selectedIds = new Set();
  const API_BASE = window.location.origin;

  // SSO: listen for user context from GHL parent
  window.addEventListener('message', async (event) => {
    if (event.data && event.data.message === 'REQUEST_USER_DATA_RESPONSE') {
      try {
        const res = await fetch(API_BASE + '/ghl/sso/decrypt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ encrypted: event.data.data }),
        });
        if (!res.ok) throw new Error('SSO decryption failed');
        sessionData = await res.json();
        initialize();
      } catch (err) {
        showStatus('Failed to authenticate: ' + err.message, 'error');
        document.getElementById('loadingState').style.display = 'none';
      }
    }
  });

  // Request SSO data
  window.parent.postMessage({ message: 'REQUEST_USER_DATA' }, '*');

  // Fallback for testing outside GHL iframe
  setTimeout(() => {
    if (!sessionData) {
      const params = new URLSearchParams(window.location.search);
      const loc = params.get('locationId');
      if (loc) { sessionData = { activeLocation: loc }; initialize(); }
      else {
        showStatus('Unable to connect. Please reload the page or try again from within GoHighLevel.', 'error');
        document.getElementById('loadingState').style.display = 'none';
      }
    }
  }, 3000);

  async function initialize() {
    document.getElementById('loadingState').style.display = 'none';
    try {
      const locId = sessionData.locationId || sessionData.activeLocation;
      const res = await fetch(API_BASE + '/ghl/app/check-setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ location_id: locId }),
      });
      const data = await res.json();
      if (data.needs_logo) {
        document.getElementById('setupSection').style.display = 'block';
      } else {
        document.getElementById('fileSection').style.display = 'block';
        loadFiles();
      }
    } catch (err) { showStatus('Error: ' + err.message, 'error'); }
  }

  // Logo upload
  const uploadZone = document.getElementById('uploadZone');
  const logoInput = document.getElementById('logoInput');
  let selectedLogoFile = null;

  uploadZone.addEventListener('click', () => logoInput.click());
  uploadZone.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone.classList.add('dragover'); });
  uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
  uploadZone.addEventListener('drop', (e) => { e.preventDefault(); uploadZone.classList.remove('dragover'); if (e.dataTransfer.files[0]) handleLogoFile(e.dataTransfer.files[0]); });
  logoInput.addEventListener('change', () => { if (logoInput.files[0]) handleLogoFile(logoInput.files[0]); });

  function handleLogoFile(file) {
    if (!file.type.startsWith('image/')) { showStatus('Please upload a PNG or JPG image.', 'error'); return; }
    selectedLogoFile = file;
    const preview = document.getElementById('logoPreview');
    preview.src = URL.createObjectURL(file);
    preview.style.display = 'block';
    document.getElementById('uploadLogoBtn').style.display = 'inline-block';
  }

  async function submitLogo() {
    if (!selectedLogoFile) return;
    const btn = document.getElementById('uploadLogoBtn');
    btn.disabled = true; btn.textContent = 'Uploading...';
    try {
      const locId = sessionData.locationId || sessionData.activeLocation;
      const fd = new FormData();
      fd.append('logo', selectedLogoFile);
      fd.append('location_id', locId);
      const res = await fetch(API_BASE + '/ghl/app/upload-logo', { method: 'POST', body: fd });
      if (!res.ok) { const err = await res.json(); throw new Error(err.error || 'Upload failed'); }
      showStatus('Logo uploaded successfully!', 'success');
      document.getElementById('setupSection').style.display = 'none';
      document.getElementById('fileSection').style.display = 'block';
      loadFiles();
    } catch (err) {
      showStatus('Logo upload failed: ' + err.message, 'error');
      btn.disabled = false; btn.textContent = 'Save Logo & Continue';
    }
  }

  // File list
  async function loadFiles() {
    const list = document.getElementById('fileList');
    list.innerHTML = '<div class="loading"><div class="spinner"></div><p>Loading files...</p></div>';
    try {
      const locId = sessionData.locationId || sessionData.activeLocation;
      const res = await fetch(API_BASE + '/ghl/app/files', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ location_id: locId }),
      });
      const data = await res.json();
      files = data.files || [];
      renderFiles();
    } catch (err) { list.innerHTML = '<div class="empty-state"><p>Failed to load files.</p></div>'; }
  }

  function refreshFiles() { selectedIds.clear(); updateToolbar(); loadFiles(); }

  function renderFiles() {
    const list = document.getElementById('fileList');
    if (files.length === 0) {
      list.innerHTML = '<div class="empty-state"><div class="icon">&#128196;</div><p>No unwatermarked PDF files found.<br>Upload PDFs to your GoHighLevel media library, then come back here.</p></div>';
      return;
    }
    list.innerHTML = files.map(f => {
      const sizeKb = f.size ? Math.round(f.size / 1024) : '?';
      const date = f.createdAt ? new Date(f.createdAt).toLocaleDateString() : '';
      return '<li class="file-item"><input type="checkbox" data-id="' + f.id + '" onchange="toggleFile(this)"' + (selectedIds.has(f.id) ? ' checked' : '') + '><span class="file-icon">&#128196;</span><div class="file-info"><div class="file-name">' + escapeHtml(f.name) + '</div><div class="file-meta">' + sizeKb + ' KB' + (date ? ' &middot; ' + date : '') + '</div></div></li>';
    }).join('');
  }

  function toggleFile(cb) { if (cb.checked) selectedIds.add(cb.dataset.id); else selectedIds.delete(cb.dataset.id); updateToolbar(); }
  function toggleSelectAll() {
    const checked = document.getElementById('selectAllBox').checked;
    selectedIds.clear();
    if (checked) files.forEach(f => selectedIds.add(f.id));
    document.querySelectorAll('.file-item input[type=checkbox]').forEach(c => c.checked = checked);
    updateToolbar();
  }
  function updateToolbar() {
    const n = selectedIds.size;
    document.getElementById('selectedCount').textContent = n + ' file' + (n !== 1 ? 's' : '') + ' selected';
    document.getElementById('watermarkBtn').disabled = n === 0;
    document.getElementById('selectAllBox').checked = n === files.length && files.length > 0;
  }

  // Watermark
  async function watermarkSelected() {
    if (selectedIds.size === 0) return;
    const overlay = document.getElementById('progressOverlay');
    const detail = document.getElementById('progressDetail');
    overlay.classList.add('visible');
    const ids = Array.from(selectedIds);
    let completed = 0, errors = [];
    const locId = sessionData.locationId || sessionData.activeLocation;
    for (const id of ids) {
      const file = files.find(f => f.id === id);
      detail.textContent = 'Processing ' + (completed + 1) + ' of ' + ids.length + ': ' + (file ? file.name : '');
      try {
        const res = await fetch(API_BASE + '/ghl/app/watermark', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ location_id: locId, file_id: id, file_name: file ? file.name : 'document.pdf', file_url: file ? file.url : null }),
        });
        if (!res.ok) { const err = await res.json(); errors.push((file ? file.name : id) + ': ' + (err.error || 'Failed')); }
        else completed++;
      } catch (err) { errors.push((file ? file.name : id) + ': ' + err.message); }
    }
    overlay.classList.remove('visible');
    selectedIds.clear(); updateToolbar();
    if (errors.length > 0) showStatus(completed + ' watermarked. ' + errors.length + ' error(s): ' + errors.join('; '), 'error');
    else showStatus(completed + ' file(s) watermarked successfully! Check your media library for the protected versions.', 'success');
    setTimeout(loadFiles, 1500);
  }

  function showStatus(msg, type) {
    const bar = document.getElementById('statusBar');
    bar.textContent = msg; bar.className = 'status-bar visible ' + (type || '');
    if (type !== 'error') setTimeout(() => bar.classList.remove('visible'), 6000);
  }
  function escapeHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
</script>
</body>
</html>`;
}

// ============================================
// ROUTE HANDLERS
// ============================================

function mountGhlRoutes(app, supabase, logger, helpers = {}) {
  const { watermarkPdf, getCachedLogo } = helpers;

  // OAuth Callback
  app.get('/ghl/oauth/callback', async (req, res) => {
    try {
      const { code } = req.query;
      if (!code) return res.status(400).send('Missing authorization code');

      logger.info('GHL OAuth callback received', { codePrefix: code.substring(0, 8) + '...' });
      const tokenData = await exchangeCodeForToken(code);

      logger.info('GHL token exchange successful', {
        userType: tokenData.userType, locationId: tokenData.locationId,
        companyId: tokenData.companyId, scope: tokenData.scope,
      });

      await storeTokens(supabase, logger, tokenData, tokenData.locationId, tokenData.companyId);

      // Try to provision Aquamark user from location email
      try {
        const locRes = await fetch(`${GHL_API_BASE}/locations/${tokenData.locationId}`, {
          headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'Accept': 'application/json', 'Version': '2021-07-28' },
        });
        if (locRes.ok) {
          const locData = await locRes.json();
          const email = locData.location?.email || locData.email;
          if (email) {
            await ensureAquamarkUser(supabase, logger, email);
            await supabase.from('ghl_tokens').update({ user_email: email }).eq('location_id', tokenData.locationId);
          }
        }
      } catch (provErr) {
        logger.warn('Could not provision user on install', { error: provErr.message });
      }

      res.send('<!DOCTYPE html><html><head><title>Aquamark Connected</title><style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f7f8fa}.card{background:white;border-radius:12px;padding:48px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.08);max-width:480px}h1{color:#1a1a2e;margin-bottom:12px}p{color:#666;line-height:1.6}.ok{font-size:48px;margin-bottom:16px}</style></head><body><div class="card"><div class="ok">&#10003;</div><h1>Aquamark Connected</h1><p>Your account has been successfully connected to Aquamark Watermarking. You can close this window and return to GoHighLevel.</p></div></body></html>');
    } catch (err) {
      logger.error('GHL OAuth callback error', { error: err.message });
      res.status(500).send('<!DOCTYPE html><html><head><title>Error</title><style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f7f8fa}.card{background:white;border-radius:12px;padding:48px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.08);max-width:480px}h1{color:#c0392b}p{color:#666;line-height:1.6}</style></head><body><div class="card"><h1>Connection Failed</h1><p>Something went wrong. Please try again or contact support@aquamark.io.</p></div></body></html>');
    }
  });

  // Webhook Receiver
  app.post('/ghl/webhook', async (req, res) => {
    try {
      res.status(200).json({ received: true });
      const event = req.body;
      logger.info('GHL webhook', { type: event.type, locationId: event.locationId });
      if (event.type === 'UNINSTALL') {
        await supabase.from('ghl_tokens').delete().eq('location_id', event.locationId);
      }
    } catch (err) { logger.error('GHL webhook error', { error: err.message }); }
  });

  // SSO Decrypt
  app.post('/ghl/sso/decrypt', async (req, res) => {
    try {
      const { encrypted } = req.body;
      if (!encrypted) return res.status(400).json({ error: 'No encrypted data' });
      const userData = decryptSsoData(encrypted);
      logger.info('GHL SSO decrypted', { userId: userData.userId, location: userData.activeLocation });
      res.json(userData);
    } catch (err) {
      logger.error('SSO decrypt error', { error: err.message });
      res.status(401).json({ error: 'SSO authentication failed' });
    }
  });

  // Custom Page UI
app.get('/ghl/app', (req, res) => {
    res.removeHeader('X-Frame-Options');
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Security-Policy', "frame-ancestors *");
    res.setHeader('X-Frame-Options', 'ALLOWALL');
    res.send(getCustomPageHtml());
});

  // Check Setup (logo exists?)
  app.post('/ghl/app/check-setup', async (req, res) => {
    try {
      const { location_id } = req.body;
      if (!location_id) return res.status(400).json({ error: 'location_id required' });

      const { data: tokenRow } = await supabase.from('ghl_tokens').select('user_email').eq('location_id', location_id).single();
      if (!tokenRow || !tokenRow.user_email) return res.json({ needs_logo: true, needs_email: true });

      const hasLogo = await checkLogoExists(supabase, tokenRow.user_email);
      res.json({ needs_logo: !hasLogo, email: tokenRow.user_email });
    } catch (err) {
      logger.error('Check setup error', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  // Logo Upload
  app.post('/ghl/app/upload-logo', async (req, res) => {
    try {
      const multer = require('multer');
      const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } }).single('logo');

      upload(req, res, async (err) => {
        if (err) return res.status(400).json({ error: 'Upload failed: ' + err.message });
        if (!req.file) return res.status(400).json({ error: 'No file provided' });

        const locationId = req.body.location_id;
        if (!locationId) return res.status(400).json({ error: 'location_id required' });

        let { data: tokenRow } = await supabase.from('ghl_tokens').select('user_email').eq('location_id', locationId).single();
        let email = tokenRow?.user_email;

        if (!email) {
          try {
            const ghlToken = await getValidToken(supabase, logger, locationId);
            const locRes = await fetch(`${GHL_API_BASE}/locations/${locationId}`, {
              headers: { 'Authorization': `Bearer ${ghlToken}`, 'Accept': 'application/json', 'Version': '2021-07-28' },
            });
            if (locRes.ok) {
              const locData = await locRes.json();
              email = locData.location?.email || locData.email;
              if (email) await supabase.from('ghl_tokens').update({ user_email: email }).eq('location_id', locationId);
            }
          } catch (e) { logger.warn('Could not fetch location email', { error: e.message }); }
        }

        if (!email) return res.status(400).json({ error: 'Could not determine account email. Please contact support@aquamark.io.' });

        await ensureAquamarkUser(supabase, logger, email);
        await uploadLogo(supabase, logger, email, req.file.buffer, req.file.originalname);
        res.json({ success: true, email });
      });
    } catch (err) {
      logger.error('Logo upload error', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  // List PDF files
  app.post('/ghl/app/files', async (req, res) => {
    try {
      const { location_id } = req.body;
      if (!location_id) return res.status(400).json({ error: 'location_id required' });

      const ghlToken = await getValidToken(supabase, logger, location_id);
      const mediaData = await listGhlMedia(ghlToken);

      const pdfFiles = (mediaData.files || []).filter(f => {
        const name = (f.name || '').toLowerCase();
        return name.endsWith('.pdf') && !name.includes('protected');
      });

      res.json({
        files: pdfFiles.map(f => ({ id: f.id, name: f.name, url: f.url, size: f.size, createdAt: f.createdAt })),
        total: pdfFiles.length,
      });
    } catch (err) {
      logger.error('List files error', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  // Watermark a file
  app.post('/ghl/app/watermark', async (req, res) => {
    try {
      const { location_id, file_name, file_url } = req.body;
      if (!location_id || !file_url) return res.status(400).json({ error: 'location_id and file_url required' });

      if (!watermarkPdf || !getCachedLogo) {
        return res.status(500).json({ error: 'Watermarking not configured. Check server setup.' });
      }

      const { data: tokenRow } = await supabase.from('ghl_tokens').select('user_email').eq('location_id', location_id).single();
      if (!tokenRow || !tokenRow.user_email) return res.status(400).json({ error: 'Please upload your logo first.' });

      const email = tokenRow.user_email;
      logger.info('GHL watermark request', { locationId: location_id, fileName: file_name, email });

      const ghlToken = await getValidToken(supabase, logger, location_id);
      const pdfBuffer = await downloadGhlMedia(ghlToken, file_url);
      const logoBytes = await getCachedLogo(email);
      const watermarkedBuffer = await watermarkPdf(Buffer.from(pdfBuffer), logoBytes, email);

      const baseName = (file_name || 'document.pdf').replace(/\.pdf$/i, '');
      const protectedName = baseName + ' protected.pdf';

      await uploadToGhlMedia(ghlToken, Buffer.from(watermarkedBuffer), protectedName);

      logger.info('GHL watermark complete', { locationId: location_id, fileName: protectedName, email });
      res.json({ success: true, filename: protectedName });
    } catch (err) {
      logger.error('GHL watermark error', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  // Status check
  app.get('/ghl/status/:locationId', async (req, res) => {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing authorization' });
      if (authHeader.split(' ')[1] !== process.env.AQUAMARK_API_KEY) return res.status(401).json({ error: 'Invalid API key' });
      const { data: tokenRow, error } = await supabase.from('ghl_tokens')
        .select('location_id, company_id, user_email, expires_at, scopes, installed_at, updated_at')
        .eq('location_id', req.params.locationId).single();
      if (error || !tokenRow) return res.status(404).json({ error: 'Location not connected' });
      res.json({ ...tokenRow, connected: true, token_status: new Date() >= new Date(tokenRow.expires_at) ? 'expired (will auto-refresh)' : 'valid' });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // List connections
  app.get('/ghl/connections', async (req, res) => {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing authorization' });
      if (authHeader.split(' ')[1] !== process.env.AQUAMARK_API_KEY) return res.status(401).json({ error: 'Invalid API key' });
      const { data: connections } = await supabase.from('ghl_tokens')
        .select('location_id, company_id, user_email, expires_at, installed_at, updated_at')
        .order('installed_at', { ascending: false });
      res.json({ total: connections ? connections.length : 0, connections: connections || [] });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  logger.info('GHL integration routes mounted (v2 with Custom Page)', {
    routes: ['GET /ghl/oauth/callback', 'POST /ghl/webhook', 'POST /ghl/sso/decrypt',
      'GET /ghl/app', 'POST /ghl/app/check-setup', 'POST /ghl/app/upload-logo',
      'POST /ghl/app/files', 'POST /ghl/app/watermark',
      'GET /ghl/status/:locationId', 'GET /ghl/connections']
  });
}

module.exports = { mountGhlRoutes, getValidToken, uploadToGhlMedia, downloadGhlMedia };
