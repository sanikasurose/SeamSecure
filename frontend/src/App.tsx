import React, { useState } from 'react';
import { analyzeThread } from './api/seamsecure';
import { ThreadResponse } from './types/api';

function App() {
const [threadText, setThreadText] = useState('');
const [result, setResult] = useState<ThreadResponse | null>(null);
const [loading, setLoading] = useState(false);
const [error, setError] = useState<string | null>(null);

  const handleAnalyze = () => {
    // For now, just log the input
    console.log('Thread text:', threadText);
    alert('Analyze clicked! (API coming next)');
  };

  return (
    <div
      style={{
        padding: '2rem',
        fontFamily: 'sans-serif',
        maxWidth: '800px',
        margin: '0 auto',
      }}
    >
      <h1>SeamSecure</h1>
      <p>Paste an email thread below to analyze potential security risks.</p>

      <textarea
        value={threadText}
        onChange={(e) => setThreadText(e.target.value)}
        placeholder="Paste the full email thread here..."
        rows={10}
        style={{
          width: '100%',
          padding: '1rem',
          fontSize: '1rem',
          marginBottom: '1rem',
        }}
      />

      <button
        onClick={handleAnalyze}
        style={{
          padding: '0.75rem 1.5rem',
          fontSize: '1rem',
          cursor: 'pointer',
        }}
      >
        Analyze Thread
      </button>
    </div>
  );
}

export default App;
