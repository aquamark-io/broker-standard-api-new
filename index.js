const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const { PDFDocument } = require("pdf-lib");
const fetch = require("node-fetch");
const { createClient } = require("@supabase/supabase-js");
const sharp = require("sharp");
const crypto = require("crypto");
const AdmZip = require("adm-zip");
const rateLimit = require("express-rate-limit");
const winston = require("winston");

const app = express();
const PORT = process.env.PORT || 10000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const MAX_FILE_SIZE = 25 * 1024 * 1024;

// Cache limits (configurable for scaling)
const MAX_LOGO_CACHE_SIZE = 200;
const MAX_TEXT_CACHE_SIZE = 1000;

// Simple caching with LRU support
const logoCache = new Map();
const textImageCache = new Map();
const authCache = new Map(); // Weekly auth caching

// Signed URL configuration
const SIGNED_URL_EXPIRY_SECONDS = 600; // 10 minutes

// ============================================
// STRUCTURED LOGGING
// ============================================
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// ============================================
// RETRY UTILITY FOR NETWORK OPERATIONS
// ============================================
async function retryOperation(fn, maxRetries = 3, operationName = 'operation') {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      const isLastAttempt = attempt === maxRetries;
      const isNetworkError = error.message.includes('fetch') || 
                            error.message.includes('timeout') ||
                            error.message.includes('ECONNREFUSED') ||
                            error.message.includes('ETIMEDOUT') ||
                            error.code === 'ENOTFOUND' ||
                            error.code === '503';
      
      if (isLastAttempt || !isNetworkError) {
        throw error;
      }
      
      const delayMs = 1000 * Math.pow(2, attempt - 1);
      logger.warn(`${operationName} failed, retrying`, { 
        attempt, 
        maxRetries, 
        delayMs,
        error: error.message 
      });
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }
}

// ============================================
// ACCESS LOGGING
// ============================================

async function logFileAccess(jobId, userEmail, action, metadata = {}) {
  try {
    const { error } = await supabase
      .from('download_access_log')
      .insert({
        job_id: jobId,
        user_email: userEmail,
        action,
        ip_address: metadata.ip || null,
        signed_url_expires_at: metadata.signedUrlExpiresAt || null,
        metadata: metadata.extra || null,
        created_at: new Date().toISOString()
      });
    
    if (error) {
      logger.error('Failed to log file access', { jobId, action, error: error.message });
    }
  } catch (err) {
    logger.error('Access logging exception', { jobId, action, error: err.message });
  }
}

async function generateSignedUrl(storagePath) {
  const { data, error } = await supabase.storage
    .from('broker-job-results')
    .createSignedUrl(storagePath, SIGNED_URL_EXPIRY_SECONDS);
  
  if (error) throw new Error('Failed to generate signed URL: ' + error.message);
  
  const expiresAt = new Date(Date.now() + SIGNED_URL_EXPIRY_SECONDS * 1000).toISOString();
  return { signedUrl: data.signedUrl, expiresAt };
}

// ============================================
// AUTO-CLEANUP: Delete expired files from storage
// ============================================

async function cleanupExpiredFiles() {
  try {
    const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000).toISOString();
    
    const { data: expiredJobs, error } = await supabase
      .from('broker_jobs')
      .select('id, storage_path, user_email')
      .eq('status', 'complete')
      .not('storage_path', 'is', null)
      .lt('completed_at', thirtyMinutesAgo);
    
    if (error) {
      logger.error('Cleanup query failed', { error: error.message });
      return;
    }
    
    if (!expiredJobs || expiredJobs.length === 0) return;
    
    logger.info('Cleanup: found expired files', { count: expiredJobs.length });
    
    for (const job of expiredJobs) {
      try {
        await deleteFromStorage(job.storage_path);
        
        await supabase
          .from('broker_jobs')
          .update({ storage_path: null, download_url: null })
          .eq('id', job.id);
        
        await logFileAccess(job.id, job.user_email, 'file_expired', {
          extra: { reason: 'auto_cleanup_30min' }
        });
        
        logger.info('Cleanup: deleted expired file', { jobId: job.id });
      } catch (delErr) {
        logger.error('Cleanup: failed to delete file', { jobId: job.id, error: delErr.message });
      }
    }
  } catch (err) {
    logger.error('Cleanup sweep failed', { error: err.message });
  }
}

setInterval(cleanupExpiredFiles, 5 * 60 * 1000);

// ============================================
// ACCESS LOG PURGE: Delete logs older than 90 days
// ============================================

const LOG_RETENTION_DAYS = 90;
let lastLogPurge = 0;

async function purgeOldAccessLogs() {
  try {
    const now = Date.now();
    if (now - lastLogPurge < 24 * 60 * 60 * 1000) return;
    lastLogPurge = now;
    
    const cutoff = new Date(now - LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
    
    const { error: logError, count: logCount } = await supabase
      .from('download_access_log')
      .delete()
      .lt('created_at', cutoff);
    
    if (logError) {
      logger.error('Log purge failed', { error: logError.message });
    } else if (logCount > 0) {
      logger.info('Access logs purged', { deletedCount: logCount, olderThan: cutoff });
    }
    
    const { error: jobError, count: jobCount } = await supabase
      .from('broker_jobs')
      .delete()
      .lt('created_at', cutoff);
    
    if (jobError) {
      logger.error('Job record purge failed', { error: jobError.message });
    } else if (jobCount > 0) {
      logger.info('Job records purged', { deletedCount: jobCount, olderThan: cutoff });
    }
  } catch (err) {
    logger.error('Log purge exception', { error: err.message });
  }
}

setInterval(purgeOldAccessLogs, 5 * 60 * 1000);

// ============================================
// WEBHOOK DELIVERY
// ============================================
async function deliverWebhook(webhookUrl, payload) {
  const payloadString = JSON.stringify(payload);
  
  const signature = crypto
    .createHmac('sha256', process.env.AQUAMARK_API_KEY)
    .update(payloadString)
    .digest('hex');
  
  const headers = {
    'Content-Type': 'application/json',
    'X-Aquamark-Signature': signature,
    'X-Aquamark-Event': payload.event,
    'X-Aquamark-Delivery': crypto.randomUUID(),
    'User-Agent': 'Aquamark-Webhooks/1.0'
  };
  
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers,
        body: payloadString,
        timeout: 10000
      });
      
      if (response.ok) {
        logger.info('Webhook delivered', { 
          webhookUrl, event: payload.event, jobId: payload.job_id, attempt, statusCode: response.status
        });
        return { success: true, statusCode: response.status, attempt };
      }
      
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        logger.warn('Webhook rejected by client', { webhookUrl, statusCode: response.status, jobId: payload.job_id });
        return { success: false, statusCode: response.status, attempt };
      }
      
      throw new Error(`Webhook endpoint returned ${response.status}`);
      
    } catch (error) {
      if (attempt === 3) {
        logger.error('Webhook delivery failed after retries', { 
          webhookUrl, event: payload.event, jobId: payload.job_id, error: error.message
        });
        return { success: false, error: error.message, attempt };
      }
      
      const delayMs = 2000 * Math.pow(2, attempt - 1);
      logger.warn('Webhook delivery failed, retrying', { webhookUrl, attempt, delayMs, error: error.message });
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }
}

// ============================================
// TIMEOUT UTILITY FOR PDF PROCESSING
// ============================================
async function processWithTimeout(fn, timeoutMs = 60000, operationName = 'PDF operation') {
  return Promise.race([
    fn(),
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error(`${operationName} timed out after ${timeoutMs/1000}s`)), timeoutMs)
    )
  ]);
}

// ============================================
// RATE LIMITING
// ============================================
const apiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 500, // 500 requests per hour per user
  message: 'Too many requests from this email. Please wait and try again.',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.body.user_email || req.ip;
  },
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', { 
      userEmail: req.body.user_email,
      ip: req.ip 
    });
    res.status(429).json({ 
      error: 'Too many requests. You have exceeded 500 requests per hour.',
      retry_after: '1 hour'
    });
  }
});

app.set('trust proxy', true);
app.use(helmet({
  contentSecurityPolicy: false,
  frameguard: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(compression());
app.use(express.json({ limit: '200mb' })); // Support base64
app.use(cors());

// ============================================
// INPUT VALIDATION MIDDLEWARE
// ============================================
function validateWatermarkRequest(req, res, next) {
  const { user_email, files } = req.body;
  
  // Validate email format
  if (!user_email || !user_email.includes('@')) {
    logger.warn('Invalid email format', { email: user_email });
    return res.status(400).json({ error: 'Valid email address required' });
  }
  
  // Validate files exist
  if (!files || !Array.isArray(files) || files.length === 0) {
    logger.warn('No files provided', { userEmail: user_email });
    return res.status(400).json({ error: 'At least one file required in "files" array' });
  }
  
  next();
}

// ============================================
// CACHE MANAGEMENT UTILITIES
// ============================================

// Validate PDF header
function isValidPdf(buffer) {
  if (!buffer || buffer.length < 5) return false;
  const header = buffer.toString('utf8', 0, 5);
  return header === '%PDF-';
}

// LRU cache: removes oldest entry when limit is reached
function setWithLRULimit(cache, key, value, maxSize) {
  if (cache.has(key)) {
    cache.delete(key);
  }
  
  if (cache.size >= maxSize) {
    const firstKey = cache.keys().next().value;
    cache.delete(firstKey);
  }
  
  cache.set(key, value);
}

// Get from cache and refresh its position
function getWithLRURefresh(cache, key) {
  if (!cache.has(key)) {
    return null;
  }
  
  const value = cache.get(key);
  cache.delete(key);
  cache.set(key, value);
  return value;
}

// Clean expired auth cache entries
function cleanExpiredAuthCache() {
  const now = Date.now();
  let removedCount = 0;
  
  for (const [email, cached] of authCache.entries()) {
    if (now >= cached.expiresAt) {
      authCache.delete(email);
      removedCount++;
    }
  }
  
  if (removedCount > 0) {
    logger.info('Auth cache cleanup', { removed: removedCount });
  }
}

// Run cleanup every hour
setInterval(cleanExpiredAuthCache, 60 * 60 * 1000);

// ============================================
// METADATA UTILITIES
// ============================================

/**
 * Adds custom metadata fields to PDF for automated processing
 * IMPORTANT: This does NOT modify existing metadata (dates, creator, etc.)
 * which would trip fraud detection. It only adds NEW custom fields.
 */
function addAquamarkMetadata(pdfDoc, userEmail) {
  const { PDFName, PDFString } = require('pdf-lib');
  
  const timestamp = new Date().toISOString();
  
  const infoDict = pdfDoc.getInfoDict();
  
  infoDict.set(PDFName.of('AquamarkProtected'), PDFString.of('true'));
  infoDict.set(PDFName.of('AquamarkBroker'), PDFString.of(userEmail)); // Changed: use full email instead of domain
  infoDict.set(PDFName.of('AquamarkTimestamp'), PDFString.of(timestamp));
  
  const existingKeywords = infoDict.get(PDFName.of('Keywords'));
  const keywordsText = existingKeywords ? existingKeywords.toString() : '';
  
  const aquamarkKeywords = `AquamarkProtected: true, AquamarkBroker: ${userEmail}`; // Changed: use full email instead of domain
  const newKeywords = keywordsText 
    ? `${keywordsText}, ${aquamarkKeywords}`
    : aquamarkKeywords;
  
  infoDict.set(PDFName.of('Keywords'), PDFString.of(newKeywords));
}

// ============================================
// CORE FUNCTIONS
// ============================================

async function getCachedLogo(userEmail) {
  const cached = getWithLRURefresh(logoCache, userEmail);
  if (cached) {
    return cached;
  }
  
  return await retryOperation(async () => {
    const { data: logoList } = await supabase.storage.from("logos").list(userEmail);
    if (!logoList || logoList.length === 0) throw new Error("No logo found");

    const actualLogos = logoList.filter(file => 
      !file.name.includes('emptyFolderPlaceholder') && 
      !file.name.includes('.emptyFolderPlaceholder') &&
      (file.name.includes('logo-') || file.name.endsWith('.png') || file.name.endsWith('.jpg'))
    );
    
    if (actualLogos.length === 0) throw new Error("No logo found");

    const logo = actualLogos[0];
    const logoPath = `${userEmail}/${logo.name}`;
    const { data: logoUrlData } = supabase.storage.from("logos").getPublicUrl(logoPath);
    const logoRes = await fetch(logoUrlData.publicUrl);
    const logoBytes = Buffer.from(await logoRes.arrayBuffer());
    
    setWithLRULimit(logoCache, userEmail, logoBytes, MAX_LOGO_CACHE_SIZE);
    return logoBytes;
  }, 3, 'Logo fetch');
}

async function checkUserAuthorization(userEmail) {
  // Check cache first
  const cached = authCache.get(userEmail);
  const now = Date.now();
  
  if (cached && now < cached.expiresAt) {
    return cached.result;
  }
  
  // Query Supabase
  const { data: user, error: userError } = await supabase
    .from("users")
    .select("plan, trial_ends_at")
    .eq("email", userEmail)
    .single();
  
  if (userError || !user) {
    throw new Error("User not found");
  }

  let result;
  
  // Check trial status for Free Trial users
  if (user.plan !== "Free Trial") {
    result = { authorized: true, user };
  } else {
    const trialEndsAt = new Date(user.trial_ends_at);
    
    if (now <= trialEndsAt.getTime()) {
      result = { authorized: true, user };
    } else {
      result = { authorized: false, reason: "Free trial has expired" };
    }
  }
  
  // Cache for 7 days
  authCache.set(userEmail, {
    result: result,
    expiresAt: now + (7 * 24 * 60 * 60 * 1000)
  });
  
  return result;
}

async function getCachedTextImage(text, logoBytes) {
  const cached = getWithLRURefresh(textImageCache, text);
  if (cached) {
    return cached;
  }
  
  const canvas = require('canvas');
  const { createCanvas } = canvas;
  const canvasInstance = createCanvas(800, 60);
  const ctx = canvasInstance.getContext('2d');
  
  ctx.fillStyle = 'rgba(255, 255, 255, 0.3)';
  ctx.fillRect(0, 0, 800, 60);
  
  ctx.font = 'bold 32px Arial';
  ctx.fillStyle = 'rgba(0, 0, 0, 0.4)';
  ctx.textAlign = 'center';
  ctx.fillText(text, 400, 40);
  
  const buffer = canvasInstance.toBuffer('image/png');
  setWithLRULimit(textImageCache, text, buffer, MAX_TEXT_CACHE_SIZE);
  
  return buffer;
}

function cleanupTempFiles(...files) {
  for (const file of files) {
    try {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    } catch (err) {
      logger.error('Temp file cleanup failed', { file, error: err.message });
    }
  }
}

async function watermarkPdf(pdfBuffer, logoBytes, userEmail) {
  const tempId = crypto.randomUUID();
  const inPath = path.join('/tmp', `temp-${tempId}-in.pdf`);
  const cleanedPath = path.join('/tmp', `temp-${tempId}-clean.pdf`);
  
  let cleanedPdfBytes;
  
  try {
    fs.writeFileSync(inPath, pdfBuffer);
    
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("PDF processing timeout (>30 seconds)")), 30000); // Increased from 15s to 30s
      
      exec(`qpdf --decrypt "${inPath}" "${cleanedPath}"`, (error, stdout, stderr) => {
        clearTimeout(timeout);
        
        if (fs.existsSync(cleanedPath) && fs.statSync(cleanedPath).size > 0) {
          resolve();
        } else {
          const stderrStr = stderr?.toString() || '';
          const errorStr = error?.message || '';
          
          // Check for password-protected PDF
          if (stderrStr.includes('password') || 
              stderrStr.includes('encrypted') || 
              stderrStr.includes('Invalid password') ||
              errorStr.includes('password')) {
            reject(new Error('This PDF is password-protected. Please remove the password and try again.'));
          } else {
            reject(new Error(`Unable to process PDF: ${stderrStr || errorStr || 'Unknown error'}`));
          }
        }
      });
    });
    
    cleanedPdfBytes = fs.readFileSync(cleanedPath);
    cleanupTempFiles(inPath, cleanedPath);
    
    const pdfDoc = await processWithTimeout(
      () => PDFDocument.load(cleanedPdfBytes, {
        ignoreEncryption: true,
        updateMetadata: false,
        throwOnInvalidObject: false
      }),
      60000,
      'PDF load'
    );
    
    cleanedPdfBytes = null; // Release memory
    
    // Create watermark
    const watermarkDoc = await PDFDocument.create();
    const watermarkImage = await watermarkDoc.embedPng(logoBytes);
    const { width, height } = pdfDoc.getPages()[0].getSize();
    const watermarkPage = watermarkDoc.addPage([width, height]);
    
    const logoWidth = 80;
    const logoHeight = (logoWidth / watermarkImage.width) * watermarkImage.height;
    
    // Hardcoded positions
    const positions = [
      { x: 35, y: 45 },
      { x: 279.8, y: 45 },
      { x: 524.6, y: 45 },
      { x: 218.6, y: 203.4 },
      { x: 463.4, y: 203.4 },
      { x: 35, y: 361.8 },
      { x: 279.8, y: 361.8 },
      { x: 524.6, y: 361.8 },
      { x: 218.6, y: 520.2 },
      { x: 463.4, y: 520.2 },
      { x: 35, y: 678.6 },
      { x: 279.8, y: 678.6 },
      { x: 524.6, y: 678.6 }
    ];
    
    positions.forEach(pos => {
      watermarkPage.drawImage(watermarkImage, {
        x: pos.x,
        y: pos.y,
        width: logoWidth,
        height: logoHeight,
        opacity: 0.25,
        rotate: { type: 'degrees', angle: 45 }
      });
    });
    
    const watermarkPdfBytes = await watermarkDoc.save();
    const watermarkEmbed = await PDFDocument.load(watermarkPdfBytes);
    const [embeddedPage] = await pdfDoc.embedPages([watermarkEmbed.getPages()[0]]);
    
    pdfDoc.getPages().forEach((page) => {
      page.drawPage(embeddedPage, { x: 0, y: 0, width, height });
    });
    
    addAquamarkMetadata(pdfDoc, userEmail);
    
    return await pdfDoc.save();
    
  } catch (error) {
    cleanupTempFiles(inPath, cleanedPath);
    throw error;
  }
}

async function createJob(jobId, userEmail, webhookUrl = null) {
  const jobData = {
    id: jobId,
    user_email: userEmail,
    status: 'processing',
    progress: 'Job created',
    created_at: new Date().toISOString()
  };
  
  if (webhookUrl) {
    jobData.webhook_url = webhookUrl;
  }
  
  await supabase
    .from('broker_jobs')
    .insert(jobData);
}

async function updateJobProgress(jobId, progress) {
  await supabase
    .from('broker_jobs')
    .update({ progress })
    .eq('id', jobId);
}

async function updateJobStatus(jobId, status, data = {}) {
  const update = {
    status,
    ...data,
    completed_at: new Date().toISOString()
  };
  
  // Clear progress when job is complete or error
  if (status === 'complete' || status === 'error') {
    update.progress = null;
  }
  
  await supabase
    .from('broker_jobs')
    .update(update)
    .eq('id', jobId);
}

async function uploadToStorage(buffer, filename) {
  const storagePath = filename;
  
  const { error } = await supabase.storage
    .from('broker-job-results')
    .upload(storagePath, buffer, {
      contentType: filename.endsWith('.zip') ? 'application/zip' : 'application/pdf',
      upsert: true
    });
  
  if (error) throw new Error(`Storage upload failed: ${error.message}`);
  
  return { storagePath };
}

async function deleteFromStorage(storagePath) {
  await supabase.storage
    .from('broker-job-results')
    .remove([storagePath]);
}

async function trackUsage(userEmail, fileCount, pageCount) {
  const now = new Date();
  const month = now.getMonth() + 1;
  const year = now.getFullYear();
  
  try {
    // Use atomic increment function to prevent race conditions during concurrent updates
    const { error } = await supabase.rpc('increment_monthly_usage', {
      p_user_email: userEmail,
      p_month: month,
      p_year: year,
      p_file_count: fileCount,
      p_page_count: pageCount
    });
    
    if (error) {
      logger.error('Error updating monthly usage', { error: error.message, userEmail });
      throw error;
    }
    
    logger.info('Updated monthly usage', { userEmail, fileCount, pageCount });
  } catch (err) {
    logger.error('Error updating monthly usage', { error: err.message, userEmail });
    // Don't throw - we don't want to fail the job if usage tracking fails
  }
}

async function processJobInBackground(jobId, userEmail, files, skipUsageTracking = false, webhookUrl = null) {
  try {
    const startTime = Date.now();
    logger.info('Processing job', { jobId, userEmail, fileCount: files.length });
    
    const logoBytes = await getCachedLogo(userEmail);
    const watermarkedFiles = [];
    let totalPageCount = 0; // Track total pages
    
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      await updateJobProgress(jobId, `Processing file ${i + 1}/${files.length}: ${file.name}`);
      
      let pdfBuffer;
      
      // Handle base64
      if (file.data) {
        try {
          const base64Data = file.data.replace(/^data:application\/pdf;base64,/, '');
          pdfBuffer = Buffer.from(base64Data, 'base64');
        } catch (error) {
          throw new Error(`File '${file.name}' has invalid base64 encoding: ${error.message}`);
        }
        
        // Validate it's actually a PDF (separate from base64 validation)
        if (!isValidPdf(pdfBuffer)) {
          throw new Error(`File '${file.name}' is not a valid PDF (corrupt or wrong file type)`);
        }
      }
      // Handle URL
      else if (file.url) {
        pdfBuffer = await retryOperation(async () => {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 30000); // 30 second timeout
          
          try {
            const response = await fetch(file.url, { signal: controller.signal });
            clearTimeout(timeout);
            
            if (!response.ok) {
              throw new Error(`Failed to download file '${file.name}' from URL (HTTP ${response.status})`);
            }
            
            const buffer = Buffer.from(await response.arrayBuffer());
            logger.info('File downloaded successfully', { filename: file.name, size: buffer.length });
            return buffer;
          } catch (error) {
            clearTimeout(timeout);
            if (error.name === 'AbortError') {
              throw new Error(`Download timeout for '${file.name}' (>30 seconds)`);
            }
            throw error;
          }
        }, 3, `Download ${file.name}`);
      }
      
      // Validate file size
      if (pdfBuffer.length > MAX_FILE_SIZE) {
        throw new Error(`File '${file.name}' exceeds 25MB limit`);
      }
      
      const watermarkedPdf = await processWithTimeout(
        () => watermarkPdf(pdfBuffer, logoBytes, userEmail),
        90000, // 90 seconds for watermarking (includes qpdf + pdf-lib operations)
        `Watermarking ${file.name}`
      );
      
      // Count pages in the watermarked PDF
      const watermarkedPdfDoc = await processWithTimeout(
        () => PDFDocument.load(watermarkedPdf, { 
          updateMetadata: false 
        }),
        30000, // 30 seconds for loading (just counting pages)
        `Loading watermarked PDF for page count`
      );
      const pageCount = watermarkedPdfDoc.getPageCount();
      totalPageCount += pageCount;
      
      watermarkedFiles.push({
        name: file.name.replace(/\.pdf$/i, '-protected.pdf'),
        data: Buffer.from(watermarkedPdf)
      });
      
      pdfBuffer = null; // Release memory
    }
    
    // Create output
    let resultBuffer;
    let resultFilename;
    
    if (watermarkedFiles.length === 1) {
      resultBuffer = watermarkedFiles[0].data;
      resultFilename = watermarkedFiles[0].name;
    } else {
      const zip = new AdmZip();
      const filenameCount = new Map(); // Track duplicate filenames
      
      watermarkedFiles.forEach(file => {
        let finalName = file.name;
        
        // Check if this filename already exists in the ZIP
        if (filenameCount.has(file.name)) {
          const count = filenameCount.get(file.name);
          filenameCount.set(file.name, count + 1);
          
          // Add number suffix: chase-statement-protected.pdf -> chase-statement-protected-1.pdf
          const lastDot = file.name.lastIndexOf('.');
          const baseName = lastDot > 0 ? file.name.substring(0, lastDot) : file.name;
          const extension = lastDot > 0 ? file.name.substring(lastDot) : '';
          finalName = `${baseName}-${count}${extension}`;
        } else {
          filenameCount.set(file.name, 1);
        }
        
        zip.addFile(finalName, file.data);
      });
      
      resultBuffer = zip.toBuffer();
      resultFilename = `${jobId}.zip`; // Use full jobId for guaranteed uniqueness
    }
    
    await updateJobProgress(jobId, 'Uploading results...');
    
    // Upload with retry logic
    let storagePath;
    try {
      logger.info('Starting storage upload', { jobId, filename: resultFilename, size: resultBuffer.length });
      const uploadResult = await retryOperation(
        async () => uploadToStorage(resultBuffer, resultFilename),
        3,
        `Storage upload for job ${jobId}`
      );
      storagePath = uploadResult.storagePath;
      logger.info('Storage upload successful', { jobId, storagePath });
    } catch (uploadError) {
      logger.error('Storage upload failed after retries', { 
        jobId, 
        error: uploadError.message,
        fileSize: resultBuffer.length 
      });
      throw new Error(`Failed to upload results: ${uploadError.message}`);
    }
    
    // Generate signed URL (time-limited, not public)
    const { signedUrl, expiresAt } = await generateSignedUrl(storagePath);
    
    await updateJobStatus(jobId, 'complete', {
      download_url: signedUrl,
      storage_path: storagePath
    });
    
    // Log the signed URL generation
    await logFileAccess(jobId, userEmail, 'link_generated', {
      signedUrlExpiresAt: expiresAt,
      extra: { source: 'job_completion' }
    });
    
    if (!skipUsageTracking) {
      await trackUsage(userEmail, files.length, totalPageCount);
    }
    
    const elapsed = Date.now() - startTime;
    logger.info('Job completed', { jobId, userEmail, fileCount: files.length, pageCount: totalPageCount, elapsedMs: elapsed });
    
    // Deliver webhook if URL was provided
    if (webhookUrl) {
      await deliverWebhook(webhookUrl, {
        event: 'job.completed',
        job_id: jobId,
        status: 'complete',
        download_url: signedUrl,
        download_expires_at: expiresAt,
        authenticated_download_url: `https://broker-standard-api-new.onrender.com/download/${jobId}`,
        file_count: files.length,
        elapsed_ms: elapsed,
        completed_at: new Date().toISOString()
      });
    }
    
  } catch (error) {
    logger.error('Job failed', { jobId, error: error.message, stack: error.stack });
    await updateJobStatus(jobId, 'error', {
      error_message: error.message
    });
    
    // Deliver webhook on failure if URL was provided
    if (webhookUrl) {
      await deliverWebhook(webhookUrl, {
        event: 'job.failed',
        job_id: jobId,
        status: 'error',
        error_message: error.message,
        completed_at: new Date().toISOString()
      });
    }
  }
}

// ============================================
// ENDPOINTS
// ============================================

app.post("/watermark", apiLimiter, validateWatermarkRequest, async (req, res) => {
  try {
    const userEmail = req.body.user_email;
    const filesParam = req.body.files;
    const webhookUrl = req.body.webhook_url || null;
    
    // Validate webhook URL if provided (must be HTTPS)
    if (webhookUrl) {
      try {
        const parsed = new URL(webhookUrl);
        if (parsed.protocol !== 'https:') {
          return res.status(400).json({ error: 'webhook_url must use HTTPS' });
        }
      } catch {
        return res.status(400).json({ error: 'webhook_url is not a valid URL' });
      }
    }
    
    // Check API key
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send("Missing authorization header");
    }
    
    const token = authHeader.split(" ")[1];
    if (token !== process.env.AQUAMARK_API_KEY) {
      return res.status(401).send("Invalid API key");
    }
    
    // Check user authorization
    const { authorized, reason } = await checkUserAuthorization(userEmail);
    if (!authorized) {
      return res.status(402).send(reason);
    }
    
    let files = [];
    const filesArray = Array.isArray(filesParam) ? filesParam : [filesParam];
    
    // Process each file object
    for (let i = 0; i < filesArray.length; i++) {
      const fileObj = filesArray[i];
      
      if (!fileObj.name) {
        return res.status(400).json({ 
          error: `File at index ${i} missing 'name' property` 
        });
      }
      
      if (fileObj.data && fileObj.url) {
        return res.status(400).json({ 
          error: `File '${fileObj.name}' has both 'data' and 'url'. Provide only one.` 
        });
      }
      
      if (!fileObj.data && !fileObj.url) {
        return res.status(400).json({ 
          error: `File '${fileObj.name}' missing 'data' or 'url' property` 
        });
      }
      
      if (!fileObj.name.toLowerCase().endsWith('.pdf')) {
        return res.status(400).json({ 
          error: `File '${fileObj.name}' must have .pdf extension` 
        });
      }
      
      files.push({
        name: fileObj.name,
        data: fileObj.data || null,
        url: fileObj.url || null
      });
    }
    
    // Create job
    const jobId = crypto.randomUUID();
    await createJob(jobId, userEmail, webhookUrl);
    
    logger.info('Job created', { jobId, userEmail, fileCount: files.length });
    
    // Start background processing
    const skipUsageTracking = req.body.skip_usage_tracking || false;
    processJobInBackground(jobId, userEmail, files, skipUsageTracking, webhookUrl).catch(err => {
      logger.error('Background job failed', { jobId, error: err.message });
    });
    
    res.json({
      job_id: jobId,
      status: 'processing',
      file_count: files.length,
      webhook_url: webhookUrl,
      message: webhookUrl
        ? 'Job created successfully. You will receive a webhook when processing completes.'
        : 'Job created successfully. Poll /job-status/{job_id} for updates.'
    });
    
  } catch (err) {
    logger.error('Error creating job', { error: err.message, stack: err.stack });
    res.status(500).send("Failed to create job: " + err.message);
  }
});

app.get("/job-status/:jobId", async (req, res) => {
  try {
    const { jobId } = req.params;
    
    const { data: job, error } = await supabase
      .from('broker_jobs')
      .select('*')
      .eq('id', jobId)
      .single();
    
    if (error || !job) {
      return res.status(404).json({ error: 'Job not found' });
    }
    
    // Check for timeout
    if (job.status === 'processing') {
      const createdAt = new Date(job.created_at);
      const now = new Date();
      const minutesElapsed = (now - createdAt) / 1000 / 60;
      
      if (minutesElapsed > 10) {
        await supabase
          .from('broker_jobs')
          .update({
            status: 'error',
            error_message: 'Job timed out after 10 minutes',
            completed_at: new Date().toISOString()
          })
          .eq('id', jobId);
        
        return res.json({
          job_id: job.id,
          status: 'error',
          error_message: 'Job timed out after 10 minutes',
          created_at: job.created_at,
          completed_at: new Date().toISOString()
        });
      }
    }
    
    // If complete and has storage path (file still exists)
    if (job.status === 'complete' && job.storage_path) {
      const { data: files } = await supabase.storage
        .from('broker-job-results')
        .list('', { search: job.storage_path });
      
      const fileExists = files && files.length > 0;
      
      if (fileExists) {
        // Generate a FRESH signed URL on every poll
        const { signedUrl, expiresAt } = await generateSignedUrl(job.storage_path);
        
        await logFileAccess(job.id, job.user_email, 'link_generated', {
          ip: req.ip,
          signedUrlExpiresAt: expiresAt,
          extra: { source: 'job_status_poll' }
        });
        
        res.json({
          job_id: job.id,
          status: job.status,
          download_url: signedUrl,
          download_expires_at: expiresAt,
          authenticated_download_url: `https://broker-standard-api-new.onrender.com/download/${job.id}`,
          message: `Ready for download. Signed link expires in ${SIGNED_URL_EXPIRY_SECONDS / 60} minutes. For logged/authenticated downloads, use the authenticated_download_url with your Bearer token.`,
          created_at: job.created_at,
          completed_at: job.completed_at
        });
      } else {
        res.json({
          job_id: job.id,
          status: job.status,
          download_url: null,
          message: 'File has been downloaded and removed, or has expired.',
          created_at: job.created_at,
          completed_at: job.completed_at
        });
      }
      
    } else if (job.status === 'error') {
      res.json({
        job_id: job.id,
        status: job.status,
        error_message: job.error_message,
        created_at: job.created_at,
        completed_at: job.completed_at
      });
    } else {
      res.json({
        job_id: job.id,
        status: job.status,
        progress: job.progress,
        created_at: job.created_at
      });
    }
    
  } catch (err) {
    logger.error('Error fetching job status', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch job status' });
  }
});

// Authenticated download — proxies file through the API with logging
app.get("/download/:jobId", async (req, res) => {
  try {
    const { jobId } = req.params;
    
    // Require Bearer token
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: 'Missing authorization header' });
    }
    
    const token = authHeader.split(" ")[1];
    if (token !== process.env.AQUAMARK_API_KEY) {
      await logFileAccess(jobId, 'unknown', 'download_denied', {
        ip: req.ip,
        extra: { reason: 'invalid_api_key' }
      });
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    // Look up the job
    const { data: job, error } = await supabase
      .from('broker_jobs')
      .select('id, user_email, storage_path, status')
      .eq('id', jobId)
      .single();
    
    if (error || !job) {
      return res.status(404).json({ error: 'Job not found' });
    }
    
    if (job.status !== 'complete') {
      return res.status(400).json({ error: 'Job is not complete', status: job.status });
    }
    
    if (!job.storage_path) {
      return res.status(410).json({ error: 'File has already been downloaded and removed, or has expired' });
    }
    
    // Download the file from Supabase storage
    const { data: fileData, error: downloadError } = await supabase.storage
      .from('broker-job-results')
      .download(job.storage_path);
    
    if (downloadError) {
      logger.error('Storage download failed', { jobId, error: downloadError.message });
      return res.status(500).json({ error: 'Failed to retrieve file from storage' });
    }
    
    // Convert to buffer
    const buffer = Buffer.from(await fileData.arrayBuffer());
    
    // Log the successful download
    await logFileAccess(jobId, job.user_email, 'file_downloaded', {
      ip: req.ip,
      extra: { file_size_bytes: buffer.length }
    });
    
    logger.info('File downloaded via authenticated endpoint', { 
      jobId, 
      userEmail: job.user_email,
      fileSize: buffer.length,
      ip: req.ip
    });
    
    // Determine content type from storage path
    const isZip = job.storage_path.endsWith('.zip');
    const contentType = isZip ? 'application/zip' : 'application/pdf';
    const filename = isZip ? `${jobId}.zip` : `${jobId}.pdf`;
    
    // Stream the file to the client
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', buffer.length);
    res.send(buffer);
    
    // Auto-delete file from storage after successful download
    try {
      await deleteFromStorage(job.storage_path);
      await supabase
        .from('broker_jobs')
        .update({ storage_path: null, download_url: null })
        .eq('id', jobId);
      
      await logFileAccess(jobId, job.user_email, 'file_deleted', {
        ip: req.ip,
        extra: { source: 'auto_delete_after_download' }
      });
      
      logger.info('File auto-deleted after download', { jobId });
    } catch (delErr) {
      logger.error('Auto-delete after download failed', { jobId, error: delErr.message });
    }
    
  } catch (err) {
    logger.error('Download endpoint error', { error: err.message, jobId: req.params.jobId });
    res.status(500).json({ error: 'Failed to process download' });
  }
});

app.get("/health", (req, res) => {
  const mem = process.memoryUsage();
  res.json({
    status: "healthy",
    memory: Math.round(mem.heapUsed / 1024 / 1024) + "MB",
    caches: {
      logos: logoCache.size,
      textImages: textImageCache.size,
      auth: authCache.size
    },
    uptime: Math.round(process.uptime()) + "s"
  });
});

app.post("/clear-cache", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send("Missing authorization");
  }

  const token = authHeader.split(" ")[1];
  if (token !== process.env.AQUAMARK_API_KEY) {
    return res.status(401).send("Invalid API key");
  }

  const logoSize = logoCache.size;
  const textSize = textImageCache.size;
  const authSize = authCache.size;
  
  logoCache.clear();
  textImageCache.clear();
  authCache.clear();
  
  logger.info('Cache cleared', { logos: logoSize, textImages: textSize, auth: authSize });
  
  res.json({ 
    cleared: { 
      logos: logoSize, 
      textImages: textSize,
      auth: authSize
    } 
  });
});

const { mountGhlRoutes } = require('./ghl-integration');
mountGhlRoutes(app, supabase, logger, { watermarkPdf, getCachedLogo });

// ============================================
// GLOBAL ERROR HANDLER
// ============================================
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { 
    error: err.message, 
    stack: err.stack,
    path: req.path,
    method: req.method
  });
  
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({
    error: isDevelopment ? err.message : 'Internal server error',
    message: 'An unexpected error occurred. Please try again.'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ============================================
// START SERVER
// ============================================


app.listen(PORT, () => {
  logger.info('Server started', { 
    port: PORT,
    cacheLimit: { logos: MAX_LOGO_CACHE_SIZE, textImages: MAX_TEXT_CACHE_SIZE }
  });
  console.log(`🚀 Aquamark Broker API v2 on port ${PORT}`);
  console.log(`📦 Cache limits: ${MAX_LOGO_CACHE_SIZE} logos, ${MAX_TEXT_CACHE_SIZE} text images`);
  console.log(`🔒 Signed URLs: ${SIGNED_URL_EXPIRY_SECONDS / 60} min expiry | Auto-cleanup: 30 min | Log retention: ${LOG_RETENTION_DAYS} days`);
});
