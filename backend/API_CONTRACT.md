# SeamSecure API Contract v1.1.0

> **Status:** PRODUCTION — Backend implements rule-based + AI-powered threat analysis.

---

## Versioning Policy

This API follows **Semantic Versioning** (`MAJOR.MINOR.PATCH`):

| Change Type | Version Bump | Backward Compatible |
|-------------|--------------|---------------------|
| Breaking schema changes | MAJOR | No |
| New features/optional fields | MINOR | Yes |
| Bug fixes/docs | PATCH | Yes |

**Current Version:** `1.1.0`

**Version History:**
| Version | Date | Changes |
|---------|------|---------|
| 1.1.0 | 2026-02-01 | Added Gemini AI analysis, `api_version` in responses, new AI indicator types |
| 1.0.0 | 2026-01-31 | Initial release with rule-based analysis |

**Client Compatibility:**
- Responses include `api_version` field for version checking
- New optional fields may be added in MINOR releases
- Existing fields will not be removed or renamed without MAJOR bump

---

## Base URL

| Environment | URL |
|-------------|-----|
| Local Dev   | `http://localhost:8000` |

---

## Endpoints

### 1. `POST /analyze-thread`

**Purpose:** Accepts an email thread and returns a security risk analysis with a score, risk level, detailed indicators, and a human-readable summary.

#### Request

| Header | Value |
|--------|-------|
| `Content-Type` | `application/json` |

**Body Schema:**

```typescript
interface ThreadRequest {
  thread_id: string;       // Unique identifier for this thread
  emails: Email[];         // Array of emails in the thread (chronological order)
}

interface Email {
  from: string;            // Email address of sender
  to: string[];            // Array of recipient email addresses
  subject: string;         // Email subject line
  timestamp: string;       // ISO-8601 datetime (required)
  body_text: string;       // Plain text email body (required)
  body_html?: string;      // HTML email body (optional)
}
```

**Example Request:**

```json
{
  "thread_id": "thread-8f3a2b1c",
  "emails": [
    {
      "from": "security@amaz0n-alerts.com",
      "to": ["john.doe@company.com"],
      "subject": "Urgent: Your account has been compromised",
      "timestamp": "2026-01-31T09:15:00Z",
      "body_text": "Dear valued customer,\n\nWe detected unusual activity on your account. Click here immediately to verify your identity: http://192.168.1.50/verify\n\nFailure to act within 24 hours will result in account suspension.\n\nPlease confirm your password to restore access.\n\nAmazon Security Team",
      "body_html": "<html><body><p>Dear valued customer,</p><p>We detected unusual activity on your account. <a href=\"http://192.168.1.50/verify\">Click here immediately</a> to verify your identity.</p></body></html>"
    },
    {
      "from": "john.doe@company.com",
      "to": ["security@amaz0n-alerts.com"],
      "subject": "Re: Urgent: Your account has been compromised",
      "timestamp": "2026-01-31T10:22:00Z",
      "body_text": "Is this legitimate? I want to verify before clicking anything."
    }
  ]
}
```

#### Response

**Status:** `200 OK`

**Body Schema:**

```typescript
interface ThreadResponse {
  thread_id: string;           // Echoed from request
  risk_score: number;          // 0.0 (safe) to 1.0 (dangerous)
  risk_level: RiskLevel;       // Categorical assessment
  indicators: RiskIndicator[]; // Detected risk signals
  summary: string;             // Human-readable explanation
  api_version: string;         // API version (e.g., "1.1.0")
}

type RiskLevel = "safe" | "suspicious" | "dangerous";

interface RiskIndicator {
  type: IndicatorType;         // Machine-readable indicator type
  description: string;         // Human-readable explanation
  severity: Severity;          // Impact level
}

// Rule-based indicators
type RuleIndicatorType =
  | "urgency_language"    // Urgent/pressuring language detected
  | "sensitive_request"   // Requests for sensitive information
  | "external_links"      // Suspicious URLs detected
  | "sender_anomaly";     // Sender address anomalies

// AI-powered indicators (when Gemini is enabled)
type AIIndicatorType =
  | "intent_drift"        // Thread intent changed suspiciously
  | "ai_urgency_detected" // AI detected urgency patterns
  | "style_anomaly"       // Writing style inconsistency
  | "sentiment_shift"     // Suspicious sentiment change
  | "ai_high_risk"        // AI classified as high-risk
  | "ai_flagged_content"; // AI flagged specific content

type IndicatorType = RuleIndicatorType | AIIndicatorType;

type Severity = "low" | "medium" | "high";
```

**Example Response:**

```json
{
  "thread_id": "thread-8f3a2b1c",
  "risk_score": 1.0,
  "risk_level": "dangerous",
  "indicators": [
    {
      "type": "urgency_language",
      "description": "Email contains urgent language patterns commonly used in phishing attempts",
      "severity": "medium"
    },
    {
      "type": "sensitive_request",
      "description": "Email requests sensitive personal or financial information",
      "severity": "high"
    },
    {
      "type": "external_links",
      "description": "Email contains links using IP addresses instead of domain names",
      "severity": "high"
    },
    {
      "type": "sender_anomaly",
      "description": "Sender domain resembles a known legitimate domain (potential impersonation)",
      "severity": "high"
    }
  ],
  "summary": "Warning: This email thread is potentially dangerous. 4 risk indicators were detected. Primary concern: Email contains links using IP addresses instead of domain names. Additional risks: sender address anomalies, requests for sensitive information, urgent or pressuring language. Do not click any links, download attachments, or provide personal information.",
  "api_version": "1.1.0"
}
```

#### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | `number` | Normalized score from 0.0 (completely safe) to 1.0 (maximum risk), capped at 1.0 |
| `risk_level` | `string` | `"safe"` (score < 0.3), `"suspicious"` (0.3 ≤ score < 0.7), `"dangerous"` (score ≥ 0.7) |
| `indicators` | `array` | List of detected risk signals; empty if no risks detected |
| `indicators[].type` | `string` | Machine-readable key for programmatic handling |
| `indicators[].description` | `string` | Human-readable explanation of the specific risk |
| `indicators[].severity` | `string` | `"low"`, `"medium"`, or `"high"` — use for visual emphasis in UI |
| `summary` | `string` | Deterministic, human-readable explanation that varies by risk level |
| `api_version` | `string` | API version that generated this response (for compatibility checks) |

#### Indicator Types Reference

**Rule-Based Indicators** (always available):

| Type | Severity | Description |
|------|----------|-------------|
| `urgency_language` | `medium` | Detects phrases like "act now", "urgent", "immediately", "verify your account" |
| `sensitive_request` | `high` | Detects requests for passwords, SSN, credit cards, bank details |
| `external_links` | `medium` or `high` | Detects URL shorteners (medium), IP-based URLs (high), suspicious TLDs (medium) |
| `sender_anomaly` | `low`, `medium`, or `high` | Detects unusual domains (low), multiple senders (medium), typosquatting (high) |

**AI-Powered Indicators** (when Gemini analysis is enabled):

| Type | Severity | Description |
|------|----------|-------------|
| `intent_drift` | `medium` or `high` | Thread started informational but shifted to action requests |
| `ai_urgency_detected` | `medium` | AI detected high urgency language patterns |
| `style_anomaly` | `medium` | Writing style inconsistent with earlier messages in thread |
| `sentiment_shift` | `medium` | Suspicious shift from positive to negative/threatening tone |
| `ai_high_risk` | `high` | AI classified message as high-risk based on content analysis |
| `ai_flagged_content` | varies | AI flagged specific suspicious content segments |

---

### 2. `GET /health`

**Purpose:** Health check endpoint for monitoring and readiness probes.

**Response:**

```json
{
  "status": "ok"
}
```

---

### 3. `GET /`

**Purpose:** Root endpoint to verify the API is running.

**Response:**

```json
{
  "message": "SeamSecure backend is running"
}
```

---

## Error Responses

| Status | Meaning | Example |
|--------|---------|---------|
| `422` | Validation error (malformed request) | Missing required field, wrong type |
| `500` | Internal server error | Unexpected backend failure |

**422 Response Example:**

```json
{
  "detail": [
    {
      "loc": ["body", "emails", 0, "from"],
      "msg": "Field required",
      "type": "missing"
    }
  ]
}
```

---

## Frontend Usage Example

### React (with async/await)

```javascript
const analyzeThread = async (threadId, emails) => {
  const response = await fetch('http://localhost:8000/analyze-thread', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      thread_id: threadId,
      emails: emails,
    }),
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }

  return response.json();
};

// Usage
const handleAnalyze = async () => {
  try {
    const result = await analyzeThread('thread-001', [
      {
        from: 'alerts@suspicious-domain.xyz',
        to: ['user@company.com'],
        subject: 'Urgent: Action Required',
        timestamp: new Date().toISOString(),
        body_text: 'Click this link immediately to verify your account: https://bit.ly/abc123',
      },
    ]);

    console.log('Risk Score:', result.risk_score);
    console.log('Risk Level:', result.risk_level);
    console.log('Indicators:', result.indicators);
    console.log('Summary:', result.summary);
  } catch (error) {
    console.error('Analysis failed:', error);
  }
};
```

### TypeScript Types (copy-paste ready)

```typescript
// types/api.ts

export interface Email {
  from: string;
  to: string[];
  subject: string;
  timestamp: string;
  body_text: string;
  body_html?: string;
}

export interface ThreadRequest {
  thread_id: string;
  emails: Email[];
}

export type RiskLevel = 'safe' | 'suspicious' | 'dangerous';
export type Severity = 'low' | 'medium' | 'high';

// Rule-based indicator types
export type RuleIndicatorType =
  | 'urgency_language'
  | 'sensitive_request'
  | 'external_links'
  | 'sender_anomaly';

// AI-powered indicator types (when Gemini is enabled)
export type AIIndicatorType =
  | 'intent_drift'
  | 'ai_urgency_detected'
  | 'style_anomaly'
  | 'sentiment_shift'
  | 'ai_high_risk'
  | 'ai_flagged_content';

export type IndicatorType = RuleIndicatorType | AIIndicatorType;

export interface RiskIndicator {
  type: IndicatorType;
  description: string;
  severity: Severity;
}

export interface ThreadResponse {
  thread_id: string;
  risk_score: number;
  risk_level: RiskLevel;
  indicators: RiskIndicator[];
  summary: string;
  api_version: string;  // Added in v1.1.0
}
```

---

## Risk Scoring Details

### Severity Weights

| Severity | Weight |
|----------|--------|
| `low` | 0.2 |
| `medium` | 0.5 |
| `high` | 0.9 |

### Risk Level Thresholds

| Score Range | Risk Level |
|-------------|------------|
| score < 0.3 | `safe` |
| 0.3 ≤ score < 0.7 | `suspicious` |
| score ≥ 0.7 | `dangerous` |

The `risk_score` is calculated by summing the weights of all detected indicators, capped at 1.0.

---

## Validation Checklist

| Item | Status |
|------|--------|
| Request model (`ThreadRequest`) is stable | ✅ |
| Response model (`ThreadResponse`) is stable | ✅ |
| All field names are finalized | ✅ |
| All field types are finalized | ✅ |
| CORS configured for React dev servers | ✅ |
| No breaking changes expected | ✅ |
| Rule-based analysis implemented | ✅ |
| AI-powered analysis implemented (v1.1.0) | ✅ |
| Deterministic summaries implemented | ✅ |
| API versioning in responses | ✅ |
| Frontend can proceed independently | ✅ |

---

## Interactive Documentation

Once the backend is running, access auto-generated docs:

| Format | URL |
|--------|-----|
| Swagger UI | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| OpenAPI JSON | http://localhost:8000/openapi.json |

---

## Notes for Frontend Team

1. **Field naming:** The sender field is `from` in JSON (not `sender`). Recipients are in the `to` array (not a single `recipient` string).

2. **Required fields:** `timestamp` and `body_text` are required for each email. The `body_html` field is optional.

3. **Thread ordering:** Send emails in chronological order (oldest first) for accurate analysis.

4. **Empty threads:** Sending an empty `emails` array is valid and will return a `"safe"` response with no indicators.

5. **Risk level mapping:** Use these thresholds for UI color coding:
   - `"safe"` → green
   - `"suspicious"` → yellow/orange
   - `"dangerous"` → red

6. **Summary usage:** The `summary` field contains a complete, human-readable explanation suitable for display to end users. It varies based on risk level and detected indicators.

7. **Indicator handling:** The `indicators` array may be empty for safe threads. Use `indicators[].type` for programmatic logic and `indicators[].description` for user display.
