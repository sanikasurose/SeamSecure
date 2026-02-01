/**
 * Rule-based indicator types detected by the backend analysis engine.
 */
export type RuleBasedIndicatorType =
  | "urgency_language"
  | "sensitive_request"
  | "external_links"
  | "sender_anomaly";

/**
 * AI-detected indicator types from the Gemini analysis service.
 */
export type AIIndicatorType =
  | "intent_drift"
  | "ai_urgency_detected"
  | "style_anomaly"
  | "sentiment_shift"
  | "ai_high_risk"
  | "ai_flagged_content";

/**
 * All possible indicator types (rule-based and AI-detected).
 */
export type IndicatorType = RuleBasedIndicatorType | AIIndicatorType;

/**
 * Represents a single email in a thread.
 * Field names match the backend Email model (backend/app/models/thread.py).
 */
export interface Email {
  /**
   * Sender email address.
   * Note: Uses "from" to match the backend JSON alias.
   */
  from: string;

  /**
   * List of recipient email addresses.
   */
  to: string[];

  /**
   * Email subject line.
   */
  subject: string;

  /**
   * ISO 8601 timestamp of when the email was sent.
   */
  timestamp: string;

  /**
   * Plain text body of the email, analyzed by the backend.
   */
  body_text: string;

  /**
   * Optional HTML body of the email.
   */
  body_html?: string;
}

/**
 * Request payload for POST /analyze-thread.
 * Emails should be in chronological order (oldest first).
 */
export interface ThreadRequest {
  thread_id: string;
  emails: Email[];
}

/**
 * Risk level classification used for UI mapping.
 * - safe: green indicator
 * - suspicious: orange indicator
 * - dangerous: red indicator
 */
export type RiskLevel = "safe" | "suspicious" | "dangerous";

/**
 * Severity level for individual risk indicators.
 */
export type Severity = "low" | "medium" | "high";

/**
 * A single risk indicator detected in the email thread.
 */
export interface RiskIndicator {
  /**
   * Machine-readable key for conditional UI logic.
   * Uses typed union of all known indicator types.
   */
  type: IndicatorType;

  /**
   * Human-readable explanation to display to the user.
   */
  description: string;

  /**
   * Severity level of this indicator.
   */
  severity: Severity;
}

/**
 * Response from the POST /analyze-thread endpoint.
 */
export interface ThreadResponse {
  /**
   * Unique identifier for the analyzed thread.
   */
  thread_id: string;

  /**
   * Normalized score from 0.0 (safe) to 1.0 (dangerous).
   */
  risk_score: number;

  /**
   * Overall risk classification for the thread.
   */
  risk_level: RiskLevel;

  /**
   * List of detected risk indicators. May be empty when risk_level is "safe".
   */
  indicators: RiskIndicator[];

  /**
   * AI-generated summary of the thread analysis.
   */
  summary: string;

  /**
   * API version string for compatibility checking.
   */
  api_version: string;
}

// ============================================================================
// Gmail Integration Types
// ============================================================================

/**
 * Represents user information from Google OAuth.
 */
export interface UserInfo {
  /**
   * User's email address.
   */
  email: string;

  /**
   * User's display name.
   */
  name: string;
}

/**
 * Response from the OAuth callback endpoint.
 */
export interface AuthCallbackResponse {
  /**
   * Session ID to use for subsequent API calls.
   */
  session_id: string;

  /**
   * Authenticated user information.
   */
  user: UserInfo;
}

/**
 * Represents a single Gmail thread from the inbox.
 */
export interface GmailThread {
  /**
   * Unique Gmail thread ID.
   */
  id: string;

  /**
   * Sender email address.
   */
  from: string;

  /**
   * Email subject line.
   */
  subject: string;

  /**
   * Date string when the email was received.
   */
  date: string;

  /**
   * Number of messages in this thread.
   */
  message_count: number;
}

/**
 * Response from GET /gmail/threads endpoint.
 */
export interface GmailThreadsResponse {
  /**
   * Status of the request.
   */
  status: string;

  /**
   * User's email address.
   */
  email: string;

  /**
   * Total number of threads returned.
   */
  thread_count: number;

  /**
   * List of Gmail threads.
   */
  threads: GmailThread[];
}

/**
 * Response from GET /auth/me endpoint.
 */
export interface AuthMeResponse {
  /**
   * User's email address.
   */
  email: string;

  /**
   * User's display name.
   */
  name: string;
}
