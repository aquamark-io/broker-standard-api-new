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

// Job concurrency control
let activeJobs = 0;
const MAX_CONCURRENT_JOBS = 3; // Process max 3 jobs at once
const jobQueue = [];

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

app.use(helmet());
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
  
  const domain = userEmail.split('@')[1] || userEmail;
  const timestamp = new Date().toISOString();
  
  const infoDict = pdfDoc.getInfoDict();
  
  infoDict.set(PDFName.of('AquamarkProtected'), PDFString.of('true'));
  infoDict.set(PDFName.of('AquamarkBroker'), PDFString.of(domain));
  infoDict.set(PDFName.of('AquamarkTimestamp'), PDFString.of(timestamp));
  
  const existingKeywords = infoDict.get(PDFName.of('Keywords'));
  const keywordsText = existingKeywords ? existingKeywords.toString() : '';
  
  const aquamarkKeywords = `AquamarkProtected: true, AquamarkBroker: ${domain}`;
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
    
    const pdfDoc = await PDFDocument.load(cleanedPdfBytes, {
      ignoreEncryption: true,
      updateMetadata: false,
      throwOnInvalidObject: false
    });
    
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

async function createJob(jobId, userEmail) {
  await supabase
    .from('broker_jobs')
    .insert({
      id: jobId,
      user_email: userEmail,
      status: 'processing',
      progress: 'Job created',
      created_at: new Date().toISOString()
    });
}

async function updateJobProgress(jobId, progress) {
  await supabase
    .from('broker_jobs')
    .update({ progress })
    .eq('id', jobId);
}

async function updateJobStatus(jobId, status, data = {}) {
  await supabase
    .from('broker_jobs')
    .update({
      status,
      ...data,
      completed_at: new Date().toISOString()
    })
    .eq('id', jobId);
}

async function uploadToStorage(buffer, filename) {
  let storagePath = filename;
  let attempt = 0;
  const maxAttempts = 10;
  
  // Try to upload, if collision occurs, add number suffix
  while (attempt < maxAttempts) {
    const { error } = await supabase.storage
      .from('broker-job-results')
      .upload(storagePath, buffer, {
        contentType: filename.endsWith('.zip') ? 'application/zip' : 'application/pdf',
        cacheControl: '3600',
        upsert: false // Don't overwrite - we want to detect collisions
      });
    
    // Success - no collision
    if (!error) {
      const { data } = supabase.storage
        .from('broker-job-results')
        .getPublicUrl(storagePath);
      
      return { storagePath, downloadUrl: data.publicUrl };
    }
    
    // If it's a collision error, try with a number
    if (error.message && error.message.includes('already exists')) {
      attempt++;
      // Extract base name and extension
      const lastDot = filename.lastIndexOf('.');
      const baseName = lastDot > 0 ? filename.substring(0, lastDot) : filename;
      const extension = lastDot > 0 ? filename.substring(lastDot) : '';
      
      storagePath = `${baseName}-${attempt}${extension}`;
      logger.debug('Storage collision, retrying with suffix', { attempt, storagePath });
    } else {
      // Some other error - throw it with context
      logger.error('Storage upload error (non-collision)', { 
        error: error.message,
        storagePath,
        bufferSize: buffer.length 
      });
      throw new Error(`Storage upload failed: ${error.message}`);
    }
  }
  
  // If we exhausted attempts, fall back to timestamp
  const timestamp = Date.now();
  storagePath = `${timestamp}-${filename}`;
  
  const { error } = await supabase.storage
    .from('broker-job-results')
    .upload(storagePath, buffer, {
      contentType: filename.endsWith('.zip') ? 'application/zip' : 'application/pdf',
      cacheControl: '3600',
      upsert: false
    });
  
  if (error) {
    logger.error('Storage upload failed', { 
      storagePath, 
      error: error.message,
      bufferSize: buffer.length 
    });
    throw new Error(`Storage upload failed: ${error.message}`);
  }
  
  const { data } = supabase.storage
    .from('broker-job-results')
    .getPublicUrl(storagePath);
  
  return { storagePath, downloadUrl: data.publicUrl };
}

async function deleteFromStorage(storagePath) {
  await supabase.storage
    .from('broker-job-results')
    .remove([storagePath]);
}

async function trackUsage(userEmail, fileCount, pageCount) {
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1; // 1-12
  
  const { data: existing, error: selectError } = await supabase
    .from('broker_monthly_usage')
    .select('*')
    .eq('user_email', userEmail)
    .eq('year', year)
    .eq('month', month)
    .single();
  
  if (existing) {
    await supabase
      .from('broker_monthly_usage')
      .update({
        file_count: existing.file_count + fileCount,
        page_count: existing.page_count + pageCount,
        updated_at: now.toISOString()
      })
      .eq('user_email', userEmail)
      .eq('year', year)
      .eq('month', month);
  } else {
    await supabase
      .from('broker_monthly_usage')
      .insert({
        user_email: userEmail,
        year,
        month,
        file_count: fileCount,
        page_count: pageCount,
        created_at: now.toISOString(),
        updated_at: now.toISOString()
      });
  }
}

async function processJobInBackground(jobId, userEmail, files, skipUsageTracking = false) {
  // Queue management - don't start if at max concurrency
  if (activeJobs >= MAX_CONCURRENT_JOBS) {
    logger.info('Job queued - at max concurrency', { jobId, activeJobs, queueLength: jobQueue.length });
    return new Promise((resolve) => {
      jobQueue.push({ jobId, userEmail, files, skipUsageTracking, resolve });
    });
  }
  
  activeJobs++;
  logger.info('Job started', { jobId, activeJobs, queuedJobs: jobQueue.length });
  
  try {
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
        if (!pdfBuffer.toString('utf8', 0, 4).includes('PDF')) {
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
      
      const watermarkedPdf = await watermarkPdf(pdfBuffer, logoBytes, userEmail);
      
      // Count pages in the watermarked PDF
      const watermarkedPdfDoc = await PDFDocument.load(watermarkedPdf, { 
        updateMetadata: false 
      });
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
      resultFilename = 'watermarked-documents.zip';
    }
    
    await updateJobProgress(jobId, 'Uploading results...');
    
    // Upload with retry logic
    let storagePath, downloadUrl;
    try {
      const uploadResult = await retryOperation(
        async () => uploadToStorage(resultBuffer, resultFilename),
        3,
        `Storage upload for job ${jobId}`
      );
      storagePath = uploadResult.storagePath;
      downloadUrl = uploadResult.downloadUrl;
    } catch (uploadError) {
      logger.error('Storage upload failed after retries', { 
        jobId, 
        error: uploadError.message,
        fileSize: resultBuffer.length 
      });
      throw new Error(`Failed to upload results: ${uploadError.message}`);
    }
    
    await updateJobStatus(jobId, 'complete', {
      download_url: downloadUrl,
      storage_path: storagePath
    });
    
    if (!skipUsageTracking) {
      await trackUsage(userEmail, files.length, totalPageCount);
    }
    
    logger.info('Job completed', { jobId, userEmail, fileCount: files.length, pageCount: totalPageCount });
    
  } catch (error) {
    logger.error('Job failed', { jobId, error: error.message, stack: error.stack });
    await updateJobStatus(jobId, 'error', {
      error_message: error.message
    });
  } finally {
    // Job finished - decrement counter and process queue
    activeJobs--;
    logger.info('Job finished', { jobId, activeJobs, queuedJobs: jobQueue.length });
    
    // Start next queued job if any
    if (jobQueue.length > 0) {
      const nextJob = jobQueue.shift();
      logger.info('Starting queued job', { jobId: nextJob.jobId, remainingQueue: jobQueue.length });
      processJobInBackground(nextJob.jobId, nextJob.userEmail, nextJob.files, nextJob.skipUsageTracking)
        .then(nextJob.resolve)
        .catch(err => {
          logger.error('Queued job failed', { jobId: nextJob.jobId, error: err.message });
          nextJob.resolve(); // Still resolve to prevent hanging
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
    await createJob(jobId, userEmail);
    
    logger.info('Job created', { jobId, userEmail, fileCount: files.length });
    
    // Start background processing
    const skipUsageTracking = req.body.skip_usage_tracking || false;
    processJobInBackground(jobId, userEmail, files, skipUsageTracking).catch(err => {
      logger.error('Background job failed', { jobId, error: err.message });
    });
    
    res.json({
      job_id: jobId,
      status: 'processing',
      file_count: files.length,
      message: 'Job created successfully. Poll /job-status/{job_id} for updates.'
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
    
    const response = {
      job_id: job.id,
      status: job.status,
      progress: job.progress,
      download_url: job.download_url,
      created_at: job.created_at,
      completed_at: job.completed_at,
      error_message: job.error_message
    };
    
    if (job.status === 'complete' && job.download_url) {
      response.message = 'Ready for download. Files expire after 1 hour.';
    }
    
    res.json(response);
    
  } catch (err) {
    logger.error('Error fetching job status', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch job status' });
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
  console.log(`✨ Features: Base64 + URL input, Multi-file support, Async processing`);
});
