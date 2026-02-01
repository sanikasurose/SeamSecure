import type { Email } from "../types/api";

/**
 * Regex pattern to match the start of an email in a thread.
 * Looks for "From:" at the start of a line, which typically indicates
 * the beginning of a new email message.
 */
const EMAIL_BOUNDARY_PATTERN = /^From:\s*/im;

/**
 * Regex patterns for extracting email headers.
 * Each pattern captures the header value after the colon.
 */
const HEADER_PATTERNS = {
  from: /^From:\s*(.+)$/im,
  to: /^To:\s*(.+)$/im,
  subject: /^Subject:\s*(.+)$/im,
  date: /^Date:\s*(.+)$/im,
};

/**
 * Extracts an email address from various formats.
 * Handles formats like:
 * - "john@example.com"
 * - "John Doe <john@example.com>"
 * - "<john@example.com>"
 *
 * @param raw - Raw string that may contain an email address
 * @returns The extracted email address, or the trimmed input if no email pattern found
 */
function extractEmailAddress(raw: string): string {
  const trimmed = raw.trim();

  // Match email in angle brackets: "Name <email@domain.com>" or "<email@domain.com>"
  const angleBracketMatch = trimmed.match(/<([^>]+)>/);
  if (angleBracketMatch) {
    return angleBracketMatch[1].trim();
  }

  // Match standalone email address
  const emailMatch = trimmed.match(/[\w.+-]+@[\w.-]+\.\w+/);
  if (emailMatch) {
    return emailMatch[0];
  }

  // Return trimmed input as fallback
  return trimmed;
}

/**
 * Parses a comma-separated list of recipients into an array of email addresses.
 * Handles multiple formats and cleans up whitespace.
 *
 * @param raw - Raw To: header value (may contain multiple recipients)
 * @returns Array of email addresses
 */
function parseRecipients(raw: string): string[] {
  if (!raw || !raw.trim()) {
    return [];
  }

  // Split on commas, but be careful with commas inside display names
  // Simple approach: split on comma followed by optional space and a word/email start
  const recipients: string[] = [];
  let current = "";
  let inAngleBrackets = false;

  for (const char of raw) {
    if (char === "<") {
      inAngleBrackets = true;
      current += char;
    } else if (char === ">") {
      inAngleBrackets = false;
      current += char;
    } else if (char === "," && !inAngleBrackets) {
      if (current.trim()) {
        recipients.push(extractEmailAddress(current));
      }
      current = "";
    } else {
      current += char;
    }
  }

  // Don't forget the last recipient
  if (current.trim()) {
    recipients.push(extractEmailAddress(current));
  }

  return recipients.filter((r) => r.length > 0);
}

/**
 * Extracts the email body from raw email text.
 * The body starts after a blank line following the headers.
 *
 * @param rawEmail - Raw email text including headers
 * @returns The email body text
 */
function extractBody(rawEmail: string): string {
  // Find the first blank line (which separates headers from body)
  // Headers end when we see a double newline
  const headerBodySplit = rawEmail.match(/\r?\n\r?\n/);

  if (headerBodySplit && headerBodySplit.index !== undefined) {
    return rawEmail.slice(headerBodySplit.index).trim();
  }

  // If no clear header/body separation, check if there are any headers
  const hasHeaders = Object.values(HEADER_PATTERNS).some((pattern) =>
    pattern.test(rawEmail)
  );

  if (hasHeaders) {
    // Try to extract body by removing header lines
    const lines = rawEmail.split(/\r?\n/);
    const bodyLines: string[] = [];
    let foundBlankLine = false;

    for (const line of lines) {
      if (foundBlankLine) {
        bodyLines.push(line);
      } else if (line.trim() === "") {
        foundBlankLine = true;
      }
    }

    return bodyLines.join("\n").trim();
  }

  // No headers found, entire text is the body
  return rawEmail.trim();
}

/**
 * Parses a single email block into a structured Email object.
 *
 * @param rawEmail - Raw text of a single email
 * @returns Parsed Email object
 */
function parseSingleEmail(rawEmail: string): Email {
  const fromMatch = rawEmail.match(HEADER_PATTERNS.from);
  const toMatch = rawEmail.match(HEADER_PATTERNS.to);
  const subjectMatch = rawEmail.match(HEADER_PATTERNS.subject);
  const dateMatch = rawEmail.match(HEADER_PATTERNS.date);

  const from = fromMatch ? extractEmailAddress(fromMatch[1]) : "unknown@unknown.com";
  const to = toMatch ? parseRecipients(toMatch[1]) : [];
  const subject = subjectMatch ? subjectMatch[1].trim() : "(No Subject)";
  const timestamp = dateMatch ? dateMatch[1].trim() : new Date().toISOString();
  const body_text = extractBody(rawEmail);

  return {
    from,
    to,
    subject,
    timestamp,
    body_text,
  };
}

/**
 * Parses raw pasted email thread text into an array of structured Email objects.
 *
 * This function handles various email formats:
 * - Standard email threads with From:, To:, Subject:, Date: headers
 * - Emails with display names like "John Doe <john@example.com>"
 * - Multiple recipients separated by commas
 * - Plain text without headers (treated as single email body)
 *
 * @param rawText - Raw email thread text pasted by the user
 * @returns Array of Email objects in chronological order (as they appear in input)
 *
 * @example
 * ```typescript
 * const emails = parseEmailThread(`
 * From: sender@example.com
 * To: recipient@example.com
 * Subject: Hello
 * Date: Mon, 1 Jan 2024 10:00:00 -0500
 *
 * This is the email body.
 * `);
 * ```
 */
export function parseEmailThread(rawText: string): Email[] {
  if (!rawText || !rawText.trim()) {
    return [];
  }

  const trimmedText = rawText.trim();

  // Check if the text contains any email headers
  const hasFromHeader = EMAIL_BOUNDARY_PATTERN.test(trimmedText);

  if (!hasFromHeader) {
    // No valid email structure found - treat entire input as a single email body
    return [
      {
        from: "unknown@unknown.com",
        to: [],
        subject: "(Pasted Content)",
        timestamp: new Date().toISOString(),
        body_text: trimmedText,
      },
    ];
  }

  // Split on email boundaries (From: headers)
  // We need to keep the delimiter, so we use a positive lookahead
  const emailBlocks = trimmedText.split(/(?=^From:\s)/im).filter((block) => block.trim());

  if (emailBlocks.length === 0) {
    // Fallback: treat as single email
    return [parseSingleEmail(trimmedText)];
  }

  // Parse each email block
  const emails: Email[] = [];

  for (const block of emailBlocks) {
    const trimmedBlock = block.trim();
    if (trimmedBlock) {
      const email = parseSingleEmail(trimmedBlock);
      // Only include if we have at least a body
      if (email.body_text || email.from !== "unknown@unknown.com") {
        emails.push(email);
      }
    }
  }

  // If parsing resulted in no valid emails, treat entire text as body
  if (emails.length === 0) {
    return [
      {
        from: "unknown@unknown.com",
        to: [],
        subject: "(Pasted Content)",
        timestamp: new Date().toISOString(),
        body_text: trimmedText,
      },
    ];
  }

  return emails;
}

/**
 * Generates a unique thread identifier for analysis requests.
 *
 * The generated ID follows the format: thread-{timestamp}-{randomString}
 * - timestamp: Current time in milliseconds for rough ordering
 * - randomString: 8-character random alphanumeric string for uniqueness
 *
 * @returns A unique thread identifier string
 *
 * @example
 * ```typescript
 * const threadId = generateThreadId();
 * // Returns something like: "thread-1704067200000-a1b2c3d4"
 * ```
 */
export function generateThreadId(): string {
  const timestamp = Date.now();
  const randomString = Math.random().toString(36).substring(2, 10);
  return `thread-${timestamp}-${randomString}`;
}
