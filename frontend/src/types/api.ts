export interface Email {
  sender: string;
  recipient: string;
  subject: string;

  /**
   * Full email body text analyzed by the backend.
   */
  body: string;

  /**
   * Optional ISO 8601 timestamp 
   */
  timestamp?: string;
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
 * Used for UI mapping (e.g., safe=green, suspicious=orange, dangerous=red).
 */
export type RiskLevel = "safe" | "suspicious" | "dangerous";

export type Severity = "low" | "medium" | "high";

export interface RiskIndicator {
  /**
   * Machine-readable key for conditional UI logic (e.g., "link_mismatch").
   */
  type: string;

  /**
   * Human-readable explanation to display to the user.
   */
  description: string;

  severity: Severity;
}

export interface ThreadResponse {
  thread_id: string;

  /**
   * Normalized score from 0.0 (safe) to 1.0 (dangerous).
   */
  risk_score: number;

  risk_level: RiskLevel;

  /**
   * May be empty when risk_level is "safe".
   */
  indicators: RiskIndicator[];

  summary: string;
}