// frontend/src/api/seamsecure.ts

import { ThreadRequest, ThreadResponse } from "../types/api.ts";

/**
 * The base URL where your FastAPI server is running locally.
 * - React dev server: http://localhost:5173
 * - FastAPI server:   http://localhost:8000
 *
 * Keeping this as a constant makes it easy to change later (deploy/Docker).
 */
const BASE_URL = "http://127.0.0.1:8000";

/**
 * Sends an email thread to SeamSecure for phishing/security analysis.
 *
 * Endpoint:
 * - POST /analyze-thread
 *
 * Request body (contract):
 * - { thread_id: string, emails: Email[] }
 *
 * Response body (contract):
 * - { thread_id, risk_score, risk_level, indicators, summary }
 *
 * @param payload The email thread you want analyzed (must match ThreadRequest).
 * @returns The analysis result from the backend (ThreadResponse).
 * @throws Error if the backend responds with a non-2xx status code.
 */
export async function analyzeThread(
  payload: ThreadRequest
): Promise<ThreadResponse> {
  // Make the HTTP request to the FastAPI endpoint using JSON.
  const res = await fetch(`${BASE_URL}/analyze-thread`, {
    method: "POST",
    headers: {
      // Required by the API contract: request body is JSON
      "Content-Type": "application/json",
    },
    // Convert the typed payload object into a JSON string for the request body
    body: JSON.stringify(payload),
  });

  // Any status outside 200–299 is considered an error (e.g., 422 validation error, 500 server error).
  if (!res.ok) {
    // Keep the error simple for now; later you can parse res.json() for FastAPI's validation details.
    throw new Error(`API error: ${res.status}`);
  }

  // Parse the JSON response into a ThreadResponse object (typed by the function return type).
  return res.json();
}