# SeamSecure API Contract v0.1.0

> **Status:** STABLE — Frontend development can proceed safely.

---

## Base URL

| Environment | URL |
|-------------|-----|
| Local Dev   | `http://localhost:8000` |

---

## Endpoints

### 1. `POST /analyze-thread`

**Purpose:** Accepts an email thread and returns a security risk analysis with a score, risk level, and detailed indicators.

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
  sender: string;          // Email address of sender
  recipient: string;       // Email address of recipient
  subject: string;         // Email subject line
  body: string;            // Full email body text
  timestamp?: string;      // ISO 8601 datetime (optional)
}
```

**Example Request:**

```json
{
  "thread_id": "thread-8f3a2b1c",
  "emails": [
    {
      "sender": "support@amaz0n-secure.com",
      "recipient": "john.doe@company.com",
      "subject": "Urgent: Your account has been compromised",
      "body": "Dear valued customer,\n\nWe detected unusual activity on your account. Click here immediately to verify your identity: http://amaz0n-secure.com/verify\n\nFailure to act within 24 hours will result in account suspension.\n\nAmazon Security Team",
      "timestamp": "2026-01-31T09:15:00Z"
    },
    {
      "sender": "john.doe@company.com",
      "recipient": "support@amaz0n-secure.com",
      "subject": "Re: Urgent: Your account has been compromised",
      "body": "Is this legitimate? I want to verify before clicking anything.",
      "timestamp": "2026-01-31T10:22:00Z"
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
  summary: string;             // Human-readable summary
}

type RiskLevel = "safe" | "suspicious" | "dangerous";

interface RiskIndicator {
  type: string;                // Machine-readable indicator type
  description: string;         // Human-readable explanation
  severity: Severity;          // Impact level
}

type Severity = "low" | "medium" | "high";
```

**Example Response:**

```json
{
  "thread_id": "thread-8f3a2b1c",
  "risk_score": 0.72,
  "risk_level": "suspicious",
  "indicators": [
    {
      "type": "urgency_language",
      "description": "Email contains urgent language patterns commonly used in phishing attempts",
      "severity": "medium"
    },
    {
      "type": "link_mismatch",
      "description": "Display text does not match actual URL destination",
      "severity": "high"
    },
    {
      "type": "sender_impersonation",
      "description": "Sender domain closely resembles a known legitimate domain",
      "severity": "medium"
    }
  ],
  "summary": "This email thread shows multiple indicators of a potential phishing attempt. Exercise caution before clicking any links or providing sensitive information."
}
```

#### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | `float` | Normalized score from 0.0 (completely safe) to 1.0 (definitely malicious) |
| `risk_level` | `string` | `"safe"` (0.0–0.3), `"suspicious"` (0.3–0.7), `"dangerous"` (0.7–1.0) |
| `indicators` | `array` | List of detected risk signals; may be empty if `risk_level` is `"safe"` |
| `indicators[].type` | `string` | Machine-readable key for programmatic handling (e.g., conditional UI) |
| `indicators[].severity` | `string` | `"low"`, `"medium"`, or `"high"` — use for visual emphasis in UI |

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

## Error Responses

| Status | Meaning | Example |
|--------|---------|---------|
| `422` | Validation error (malformed request) | Missing required field |
| `500` | Internal server error | Unexpected backend failure |

**422 Response Example:**

```json
{
  "detail": [
    {
      "loc": ["body", "thread_id"],
      "msg": "field required",
      "type": "value_error.missing"
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
        sender: 'attacker@phishing.com',
        recipient: 'victim@company.com',
        subject: 'Urgent: Action Required',
        body: 'Click this link immediately...',
        timestamp: new Date().toISOString(),
      },
    ]);

    console.log('Risk Score:', result.risk_score);
    console.log('Risk Level:', result.risk_level);
    console.log('Indicators:', result.indicators);
  } catch (error) {
    console.error('Analysis failed:', error);
  }
};
```

### TypeScript Types (copy-paste ready)

```typescript
// types/api.ts

export interface Email {
  sender: string;
  recipient: string;
  subject: string;
  body: string;
  timestamp?: string;
}

export interface ThreadRequest {
  thread_id: string;
  emails: Email[];
}

export type RiskLevel = 'safe' | 'suspicious' | 'dangerous';
export type Severity = 'low' | 'medium' | 'high';

export interface RiskIndicator {
  type: string;
  description: string;
  severity: Severity;
}

export interface ThreadResponse {
  thread_id: string;
  risk_score: number;
  risk_level: RiskLevel;
  indicators: RiskIndicator[];
  summary: string;
}
```

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
| Stub returns realistic mock data | ✅ |
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

1. **Stub behavior:** The endpoint currently returns the same mock response for all inputs. This is intentional — real analysis logic comes later.

2. **Timestamps:** The `timestamp` field is optional. If omitted, backend will not fail. Include it when available for future analysis accuracy.

3. **Thread ordering:** Send emails in chronological order (oldest first). This will matter when real analysis is implemented.

4. **Empty threads:** Sending an empty `emails` array is valid but will return a `"safe"` response in production.

5. **Risk level mapping:** Use these thresholds for UI color coding:
   - `"safe"` → green
   - `"suspicious"` → yellow/orange  
   - `"dangerous"` → red
