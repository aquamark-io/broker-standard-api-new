# Aquamark Broker API v2

Modern async watermarking API for brokers with support for base64, URLs, and multiple files per request.

## Features

- ✅ **Multiple file formats**: Base64 data and URLs in the same request
- ✅ **Batch processing**: Submit multiple files at once
- ✅ **Async job processing**: No timeouts on large batches
- ✅ **LRU caching**: Automatic logo and auth caching with memory management
- ✅ **Rate limiting**: 100 requests per 15 minutes per user
- ✅ **Structured logging**: Winston for production-grade logs
- ✅ **Weekly auth caching**: Reduced database load
- ✅ **Memory optimized**: Automatic cleanup and efficient buffer handling

## API Endpoints

### POST /watermark

Submit files for watermarking.

**Request:**
```json
{
  "user_email": "broker@example.com",
  "files": [
    {
      "name": "statement.pdf",
      "data": "base64_encoded_pdf_data..."
    },
    {
      "name": "credit-app.pdf",
      "url": "https://example.com/file.pdf"
    }
  ]
}
```

**Headers:**
```
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
```

**Response:**
```json
{
  "job_id": "abc123...",
  "status": "processing",
  "file_count": 2,
  "message": "Job created successfully. Poll /job-status/{job_id} for updates."
}
```

### GET /job-status/:jobId

Check job processing status.

**Response (Processing):**
```json
{
  "job_id": "abc123...",
  "status": "processing",
  "progress": "Processing file 1/2: statement.pdf",
  "created_at": "2025-01-01T12:00:00Z"
}
```

**Response (Complete):**
```json
{
  "job_id": "abc123...",
  "status": "complete",
  "download_url": "https://...",
  "message": "Ready for download. Files expire after 1 hour.",
  "created_at": "2025-01-01T12:00:00Z",
  "completed_at": "2025-01-01T12:01:30Z"
}
```

**Response (Error):**
```json
{
  "job_id": "abc123...",
  "status": "error",
  "error_message": "File 'doc.pdf' exceeds 25MB limit",
  "created_at": "2025-01-01T12:00:00Z",
  "completed_at": "2025-01-01T12:00:15Z"
}
```

### GET /health

Health check and cache statistics.

**Response:**
```json
{
  "status": "healthy",
  "memory": "245MB",
  "caches": {
    "logos": 12,
    "textImages": 45,
    "auth": 8
  },
  "uptime": "86400s"
}
```

### POST /clear-cache

Clear all caches (requires API key).

**Headers:**
```
Authorization: Bearer YOUR_API_KEY
```

## File Input Formats

### Base64 Input
```json
{
  "name": "document.pdf",
  "data": "JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PC9UeXBl..."
}
```

### URL Input
```json
{
  "name": "document.pdf",
  "url": "https://example.com/files/document.pdf"
}
```

## Environment Variables

Required:
- `AQUAMARK_API_KEY` - API authentication key
- `SUPABASE_URL` - Supabase project URL
- `SUPABASE_KEY` - Supabase service key
- `PORT` - Server port (default: 10000)

## Database Tables

Uses existing Aquamark tables:
- `users` - User authentication and trial status
- `broker_jobs` - Job tracking and status
- `broker_monthly_usage` - Usage tracking
- `broker-job-results` (storage bucket) - Temporary result storage

## Deployment

### Docker
```bash
docker build -t aquamark-broker-v2 .
docker run -p 10000:10000 \
  -e AQUAMARK_API_KEY=your_key \
  -e SUPABASE_URL=your_url \
  -e SUPABASE_KEY=your_key \
  aquamark-broker-v2
```

### Render
1. Connect this GitHub repo
2. Set environment variables
3. Deploy

## Rate Limits

- 100 requests per 15 minutes per user email
- 25MB max file size per file
- 200MB max request body (for base64 files)
- 10 minute timeout per job

## Response Times

- Job creation: < 1 second
- Single file processing: 2-10 seconds
- Batch processing: scales linearly (~5-7 sec per file)
- Files expire 1 hour after completion

## Differences from v1

| Feature | v1 (Legacy) | v2 (This API) |
|---------|-------------|---------------|
| File input | Upload only | Base64 + URL |
| Multiple files | No | Yes |
| Processing | Synchronous | Async jobs |
| Timeout risk | High | None |
| Memory usage | High | Optimized |
| Auth caching | None | 7 days |
| Logo caching | Daily | LRU with limits |

## Support

For issues or questions, contact support@aquamark.io
