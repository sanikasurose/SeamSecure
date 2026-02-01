// frontend/src/api/gmail.ts

import {
  GmailThreadsResponse,
  ThreadResponse,
  AuthMeResponse,
  AuthCallbackResponse,
} from "../types/api";

/**
 * Base URL for the backend API.
 */
const BASE_URL = "http://127.0.0.1:8000";

/**
 * Initiates Google OAuth flow by opening a popup window.
 * Returns a promise that resolves with the session_id when authentication completes.
 *
 * @returns Promise resolving to AuthCallbackResponse with session_id and user info
 * @throws Error if the popup is blocked or authentication fails
 */
export function initiateGoogleLogin(): Promise<AuthCallbackResponse> {
  return new Promise((resolve, reject) => {
    // Calculate popup window dimensions and position
    const width = 500;
    const height = 600;
    const left = window.screenX + (window.outerWidth - width) / 2;
    const top = window.screenY + (window.outerHeight - height) / 2;

    // Open the OAuth popup
    const popup = window.open(
      `${BASE_URL}/auth/google`,
      "Google Login",
      `width=${width},height=${height},left=${left},top=${top},popup=1`
    );

    if (!popup) {
      reject(new Error("Popup was blocked. Please allow popups for this site."));
      return;
    }

    // Poll the popup to check when it reaches the callback URL
    const pollInterval = setInterval(() => {
      try {
        // Check if popup is closed without completing auth
        if (popup.closed) {
          clearInterval(pollInterval);
          reject(new Error("Authentication was cancelled."));
          return;
        }

        // Try to access the popup's location (will throw if cross-origin)
        const popupUrl = popup.location.href;

        // Check if we've reached the callback URL
        if (popupUrl.includes("/auth/google/callback")) {
          clearInterval(pollInterval);

          // The callback returns JSON directly, so we need to fetch the content
          // First, let's read the popup's document body
          const bodyText = popup.document.body.innerText;

          try {
            const data = JSON.parse(bodyText) as AuthCallbackResponse;
            popup.close();
            resolve(data);
          } catch {
            popup.close();
            reject(new Error("Failed to parse authentication response."));
          }
        }
      } catch {
        // Cross-origin error is expected while on Google's domain
        // Just continue polling
      }
    }, 500);

    // Timeout after 5 minutes
    setTimeout(() => {
      clearInterval(pollInterval);
      if (!popup.closed) {
        popup.close();
      }
      reject(new Error("Authentication timed out."));
    }, 5 * 60 * 1000);
  });
}

/**
 * Fetches Gmail threads for the authenticated user.
 *
 * @param sessionId - The session ID from OAuth authentication
 * @param maxResults - Maximum number of threads to return (default: 10)
 * @returns Promise resolving to GmailThreadsResponse
 * @throws Error if the request fails
 */
export async function getGmailThreads(
  sessionId: string,
  maxResults: number = 10
): Promise<GmailThreadsResponse> {
  const res = await fetch(
    `${BASE_URL}/gmail/threads?session_id=${encodeURIComponent(sessionId)}&max_results=${maxResults}`,
    {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Failed to fetch threads: ${res.status} - ${errorText}`);
  }

  return res.json();
}

/**
 * Analyzes a Gmail thread for security risks.
 *
 * @param sessionId - The session ID from OAuth authentication
 * @param threadId - The Gmail thread ID to analyze
 * @returns Promise resolving to ThreadResponse with analysis results
 * @throws Error if the request fails
 */
export async function analyzeGmailThread(
  sessionId: string,
  threadId: string
): Promise<ThreadResponse> {
  const res = await fetch(
    `${BASE_URL}/gmail/analyze/${encodeURIComponent(threadId)}?session_id=${encodeURIComponent(sessionId)}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Failed to analyze thread: ${res.status} - ${errorText}`);
  }

  return res.json();
}

/**
 * Gets the current user information.
 *
 * @param sessionId - The session ID from OAuth authentication
 * @returns Promise resolving to AuthMeResponse with user info
 * @throws Error if the request fails
 */
export async function getCurrentUser(sessionId: string): Promise<AuthMeResponse> {
  const res = await fetch(
    `${BASE_URL}/auth/me?session_id=${encodeURIComponent(sessionId)}`,
    {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Failed to get user info: ${res.status} - ${errorText}`);
  }

  return res.json();
}

/**
 * Logs out the user and invalidates the session.
 *
 * @param sessionId - The session ID to invalidate
 * @returns Promise resolving when logout is complete
 * @throws Error if the request fails
 */
export async function logout(sessionId: string): Promise<void> {
  const res = await fetch(
    `${BASE_URL}/auth/logout?session_id=${encodeURIComponent(sessionId)}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Failed to logout: ${res.status} - ${errorText}`);
  }
}
