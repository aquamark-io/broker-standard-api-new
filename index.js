// ============================================
// CRITICAL SECURITY PATCHES FOR BROKER API
// ============================================

// PATCH 1: Add file size validation in validateWatermarkRequest
// Replace lines 131-147 with:

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
  
  // NEW: Validate file count
  if (files.length > 50) {
    logger.warn('Too many files', { userEmail: user_email, count: files.length });
    return res.status(400).json({ error: 'Maximum 50 files per request' });
  }
  
  // NEW: Validate individual file sizes and total size
  let totalSize = 0;
  const oversizedFiles = [];
  
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    
    if (file.data) {
      const fileSize = Buffer.from(file.data, 'base64').length;
      totalSize += fileSize;
      
      if (fileSize > MAX_FILE_SIZE) {
        oversizedFiles.push({
          name: file.name || `File ${i}`,
          size: `${(fileSize / 1024 / 1024).toFixed(2)}MB`
        });
      }
    }
    // Note: We don't validate URL-based files here since we don't know their size
    // until we fetch them. This is validated later in downloadPdfFromUrl().
  }
  
  if (oversizedFiles.length > 0) {
    logger.warn('Files exceed size limit', { 
      userEmail: user_email, 
      oversizedFiles 
    });
    return res.status(413).json({ 
      error: 'One or more files exceed 25MB limit',
      oversized_files: oversizedFiles,
      max_size: '25MB'
    });
  }
  
  if (totalSize > MAX_FILE_SIZE * 2) { // Allow 2x for multiple small files
    logger.warn('Total size exceeds limit', { 
      userEmail: user_email, 
      totalSize: `${(totalSize / 1024 / 1024).toFixed(2)}MB` 
    });
    return res.status(413).json({ 
      error: 'Total file size exceeds 50MB limit',
      total_size: `${(totalSize / 1024 / 1024).toFixed(2)}MB`,
      max_total: '50MB'
    });
  }
  
  next();
}

// ============================================
// PATCH 2: Add timeout to logo fetch
// Replace getCachedLogo function starting at line 242 with:
// ============================================

async function fetchWithTimeout(url, timeout = 30000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error('Fetch timeout after 30 seconds');
    }
    throw error;
  }
}

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
    
    // CHANGE: Use fetchWithTimeout instead of fetch
    const logoRes = await fetchWithTimeout(logoUrlData.publicUrl);
    if (!logoRes.ok) throw new Error("Logo fetch failed");

    const logoBuffer = await logoRes.arrayBuffer();
    const pngBuffer = await sharp(Buffer.from(logoBuffer)).resize(null, 130).png().toBuffer();

    const result = { buffer: pngBuffer };
    setWithLRULimit(logoCache, userEmail, result, MAX_LOGO_CACHE_SIZE);
    return result;
  }, 3, 'Logo fetch');
}

// ============================================
// PATCH 3: Add comprehensive PDF validation
// Replace isValidPdf function at line 154 with:
// ============================================

async function isValidPdf(buffer) {
  if (!buffer || buffer.length < 5) return false;
  
  // Check PDF header
  const header = buffer.toString('utf8', 0, 5);
  if (header !== '%PDF-') return false;
  
  // Try to actually load the PDF to ensure it's not corrupted
  try {
    const pdfDoc = await PDFDocument.load(buffer, { 
      updateMetadata: false,
      ignoreEncryption: true 
    });
    return pdfDoc.getPageCount() > 0;
  } catch (error) {
    logger.warn('PDF validation failed on load', { error: error.message });
    return false;
  }
}

// ============================================
// PATCH 4: Validate file size from URL downloads
// This should be added to the downloadPdfFromUrl function
// (which is in the truncated section, but needs this check)
// ============================================

// Add this check after downloading from URL but before processing:

const buffer = await urlResponse.arrayBuffer();

// NEW: Check downloaded file size
if (buffer.byteLength > MAX_FILE_SIZE) {
  throw new Error(
    `Downloaded file exceeds 25MB limit: ${(buffer.byteLength / 1024 / 1024).toFixed(2)}MB`
  );
}

const isValid = await isValidPdf(Buffer.from(buffer));
if (!isValid) {
  throw new Error(`URL does not point to a valid PDF: ${url}`);
}

// Continue with processing...

// ============================================
// REQUIRED DEPENDENCY
// ============================================
// Add to package.json: "abort-controller": "^3.0.0"
// Then: npm install abort-controller

// At top of file add:
const AbortController = require('abort-controller');
