// React hook for managing component state
import { useState } from "react";

// API function to analyze email threads
import { analyzeThread } from "./api/seamsecure";

// Type definition for the thread analysis response
import { ThreadResponse } from "./types/api";

// UI components for displaying risk information
import { RiskBadge } from "./components/RiskBadge";
import { IndicatorList } from "./components/IndicatorList";

function App() {
    // Hold the API response and loading state
  const [result, setResult] = useState<ThreadResponse | null>(null);
  
    // Used to indicate if the analysis is in progress
  const [loading, setLoading] = useState(false);

  // Called when the usser clicks the button
  const handleAnalyze = async () => {
    setLoading(true);

    try {
        // Call the backend API to analyze a sample email thread
      const res = await analyzeThread({
        thread_id: "thread-001",
        emails: [
          {
            sender: "support@amaz0n-secure.com",
            recipient: "user@company.com",
            subject: "Urgent: Account Issue",
            body: "Click here immediately to verify your account.",
          },
        ],
      });

      // Save the response to state
      setResult(res);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "2rem", maxWidth: 600 }}>
      <h1>SeamSecure</h1>

      <button onClick={handleAnalyze} disabled={loading}>
        {loading ? "Analyzing..." : "Analyze Thread"}
      </button>

      {result && (
        <>
          <h2>
            Risk Level: <RiskBadge level={result.risk_level} />
          </h2>
          <p>Risk Score: {result.risk_score}</p>
          <p>{result.summary}</p>
          <IndicatorList indicators={result.indicators} />
        </>
      )}
    </div>
  );
}

export default App;