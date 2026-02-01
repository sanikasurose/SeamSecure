import React, { useState, useEffect } from 'react';
import { analyzeThread } from './api/seamsecure';
import { ThreadResponse, GmailThread, UserInfo } from './types/api';
import { parseEmailThread, generateThreadId } from './utils/emailParser';
import { RiskBadge } from './components/RiskBadge';
import { IndicatorList } from './components/IndicatorList';
import { GmailThreadList } from './components/GmailThreadList';
import {
  getGmailThreads,
  analyzeGmailThread,
  logout,
  getCurrentUser,
} from './api/gmail';

// Tab type for navigation
type TabType = 'paste' | 'gmail';

// Local storage key for session persistence
const SESSION_STORAGE_KEY = 'seamsecure_session_id';

// Icons as components for cleaner JSX
const ShieldIcon = () => (
  <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);

const MailIcon = () => (
  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="16" rx="2" />
    <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
  </svg>
);

const InboxIcon = () => (
  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="22 12 16 12 14 15 10 15 8 12 2 12" />
    <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
  </svg>
);

const RefreshIcon = ({ spinning = false }: { spinning?: boolean }) => (
  <svg className={`w-4 h-4 ${spinning ? 'spinner' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
    <path d="M21 3v5h-5" />
  </svg>
);

const LogoutIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
    <polyline points="16 17 21 12 16 7" />
    <line x1="21" y1="12" x2="9" y2="12" />
  </svg>
);

const GoogleIcon = () => (
  <svg className="w-5 h-5" viewBox="0 0 24 24">
    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
  </svg>
);

const LoadingSpinner = () => (
  <svg className="w-5 h-5 spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10" strokeOpacity="0.25" />
    <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" />
  </svg>
);

const ThreadPatternBg = () => (
  <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-30">
    <svg className="absolute w-full h-full" preserveAspectRatio="none">
      <defs>
        <pattern id="thread-pattern" x="0" y="0" width="40" height="40" patternUnits="userSpaceOnUse">
          <circle cx="20" cy="20" r="1" fill="currentColor" className="text-cyan-500" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#thread-pattern)" />
    </svg>
  </div>
);

function App() {
  // Tab navigation state
  const [activeTab, setActiveTab] = useState<TabType>('paste');

  // Paste email tab state
  const [threadText, setThreadText] = useState('');
  const [result, setResult] = useState<ThreadResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Gmail tab state
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [gmailThreads, setGmailThreads] = useState<GmailThread[]>([]);
  const [gmailLoading, setGmailLoading] = useState(false);
  const [gmailError, setGmailError] = useState<string | null>(null);

  // Gmail analysis state
  const [analyzingThreadId, setAnalyzingThreadId] = useState<string | null>(null);
  const [analysisResults, setAnalysisResults] = useState<Record<string, ThreadResponse>>({});
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  // Restore session from URL params or localStorage on mount
  useEffect(() => {
    // Check URL params first (from OAuth redirect)
    const urlParams = new URLSearchParams(window.location.search);
    const urlSessionId = urlParams.get('session_id');
    const urlEmail = urlParams.get('email');
    const urlName = urlParams.get('name');

    if (urlSessionId) {
      // Got session from OAuth redirect
      setSessionId(urlSessionId);
      setUserInfo({ email: urlEmail || '', name: urlName || '' });
      localStorage.setItem(SESSION_STORAGE_KEY, urlSessionId);
      
      // Clean up URL params
      window.history.replaceState({}, '', window.location.pathname);
      
      // Switch to Gmail tab
      setActiveTab('gmail');
      return;
    }

    // Fall back to localStorage
    const storedSessionId = localStorage.getItem(SESSION_STORAGE_KEY);
    if (storedSessionId) {
      // Verify the session is still valid
      getCurrentUser(storedSessionId)
        .then((user) => {
          setSessionId(storedSessionId);
          setUserInfo({ email: user.email, name: user.name });
        })
        .catch(() => {
          // Session expired or invalid, clear it
          localStorage.removeItem(SESSION_STORAGE_KEY);
        });
    }
  }, []);

  // Fetch Gmail threads when session is available
  useEffect(() => {
    if (sessionId && activeTab === 'gmail') {
      fetchGmailThreads();
    }
  }, [sessionId, activeTab]);

  const fetchGmailThreads = async () => {
    if (!sessionId) return;

    setGmailLoading(true);
    setGmailError(null);

    try {
      const response = await getGmailThreads(sessionId, 10);
      setGmailThreads(response.threads);
    } catch (err) {
      if (err instanceof Error) {
        setGmailError(err.message);
      } else {
        setGmailError('Failed to fetch Gmail threads.');
      }
    } finally {
      setGmailLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    // Redirect to Google OAuth - will redirect back to frontend after auth
    window.location.href = 'http://127.0.0.1:8000/auth/google';
  };

  const handleLogout = async () => {
    if (!sessionId) return;

    try {
      await logout(sessionId);
    } catch {
      // Ignore logout errors, clear session anyway
    }

    setSessionId(null);
    setUserInfo(null);
    setGmailThreads([]);
    setAnalysisResults({});
    localStorage.removeItem(SESSION_STORAGE_KEY);
  };

  const handleAnalyzeGmailThread = async (threadId: string) => {
    if (!sessionId) return;

    setAnalyzingThreadId(threadId);
    setAnalysisError(null);

    try {
      const response = await analyzeGmailThread(sessionId, threadId);
      setAnalysisResults((prev) => ({
        ...prev,
        [threadId]: response,
      }));
    } catch (err) {
      if (err instanceof Error) {
        setAnalysisError(err.message);
      } else {
        setAnalysisError('Failed to analyze thread.');
      }
    } finally {
      setAnalyzingThreadId(null);
    }
  };

  const handleAnalyze = async () => {
    // Validate that threadText is not empty
    if (!threadText.trim()) {
      setError('Please paste an email thread to analyze.');
      return;
    }

    // Set loading state and clear previous results
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      // Parse the raw text into structured emails
      const emails = parseEmailThread(threadText);

      // Generate a unique thread ID
      const thread_id = generateThreadId();

      // Call the backend API
      const response = await analyzeThread({ thread_id, emails });

      // Set the result on success
      setResult(response);
    } catch (err) {
      // Handle errors and set error message
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred.');
      }
    } finally {
      // Always set loading to false
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen relative">
      {/* Background pattern */}
      <ThreadPatternBg />
      
      {/* Main container */}
      <div className="relative z-10 max-w-4xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <header className="mb-8 animate-[fade-in_0.5s_ease-out]">
          <div className="flex items-center gap-3 mb-2">
            <div className="text-cyan-400">
              <ShieldIcon />
            </div>
            <h1 className="text-3xl sm:text-4xl font-bold gradient-text">
              SeamSecure
            </h1>
          </div>
          <p className="text-slate-400 text-lg">
            AI-powered email security analysis to protect you from phishing threats
          </p>
        </header>

        {/* Tab Navigation */}
        <nav className="flex gap-1 mb-8 border-b border-slate-700/50 animate-[slide-up_0.4s_ease-out]">
          <button
            onClick={() => setActiveTab('paste')}
            className={`tab flex items-center gap-2 ${activeTab === 'paste' ? 'tab-active' : ''}`}
          >
            <MailIcon />
            <span>Paste Email</span>
          </button>
          <button
            onClick={() => setActiveTab('gmail')}
            className={`tab flex items-center gap-2 ${activeTab === 'gmail' ? 'tab-active' : ''}`}
          >
            <InboxIcon />
            <span>Gmail Inbox</span>
          </button>
        </nav>

        {/* Paste Email Tab */}
        {activeTab === 'paste' && (
          <div className="space-y-6 animate-[fade-in_0.3s_ease-out]">
            <div className="card p-6">
              <label htmlFor="email-input" className="block text-sm font-medium text-slate-300 mb-3">
                Paste your email thread below to analyze for potential security risks
              </label>
              <textarea
                id="email-input"
                value={threadText}
                onChange={(e) => setThreadText(e.target.value)}
                placeholder="Paste the full email thread here including headers (From, To, Subject, Date) and body..."
                rows={12}
                disabled={loading}
                className="input font-mono text-sm leading-relaxed"
              />
              
              <div className="mt-4 flex flex-wrap items-center gap-3">
                <button
                  onClick={handleAnalyze}
                  disabled={loading}
                  className="btn btn-primary"
                >
                  {loading ? (
                    <>
                      <LoadingSpinner />
                      <span>Analyzing...</span>
                    </>
                  ) : (
                    <>
                      <ShieldIcon />
                      <span>Analyze Thread</span>
                    </>
                  )}
                </button>
                
                {threadText && !loading && (
                  <button
                    onClick={() => {
                      setThreadText('');
                      setResult(null);
                      setError(null);
                    }}
                    className="btn btn-secondary"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>

            {/* Error display */}
            {error && (
              <div className="error-message animate-[slide-up_0.3s_ease-out]">
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="12" y1="8" x2="12" y2="12" />
                    <line x1="12" y1="16" x2="12.01" y2="16" />
                  </svg>
                  <span>{error}</span>
                </div>
              </div>
            )}

            {/* Results display */}
            {result && (
              <div className={`card p-6 animate-[slide-up_0.4s_ease-out] ${
                result.risk_level === 'safe' ? 'border-emerald-500/30' :
                result.risk_level === 'suspicious' ? 'border-amber-500/30' :
                'border-red-500/30'
              }`}>
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                    <svg className="w-5 h-5 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                    </svg>
                    Analysis Results
                  </h2>
                </div>

                {/* Risk Level & Score */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
                  <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/50">
                    <div className="text-sm text-slate-400 mb-2">Risk Level</div>
                    <RiskBadge level={result.risk_level} />
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/50">
                    <div className="text-sm text-slate-400 mb-2">Risk Score</div>
                    <div className="flex items-center gap-3">
                      <div className="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full transition-all duration-500 ${
                            result.risk_level === 'safe' ? 'bg-emerald-500' :
                            result.risk_level === 'suspicious' ? 'bg-amber-500' :
                            'bg-red-500'
                          }`}
                          style={{ width: `${result.risk_score * 100}%` }}
                        />
                      </div>
                      <span className={`font-semibold text-lg ${
                        result.risk_level === 'safe' ? 'text-emerald-400' :
                        result.risk_level === 'suspicious' ? 'text-amber-400' :
                        'text-red-400'
                      }`}>
                        {Math.round(result.risk_score * 100)}%
                      </span>
                    </div>
                  </div>
                </div>

                {/* Summary */}
                <div className="mb-6">
                  <h3 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
                    <svg className="w-4 h-4 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M4 6h16M4 12h16M4 18h7" />
                    </svg>
                    Summary
                  </h3>
                  <p className="text-slate-300 leading-relaxed bg-slate-900/30 rounded-lg p-4 border border-slate-700/30">
                    {result.summary}
                  </p>
                </div>

                {/* Risk Indicators */}
                <div>
                  <h3 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                    <svg className="w-4 h-4 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                      <line x1="12" y1="9" x2="12" y2="13" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    Risk Indicators
                  </h3>
                  <IndicatorList indicators={result.indicators} />
                </div>
              </div>
            )}
          </div>
        )}

        {/* Gmail Inbox Tab */}
        {activeTab === 'gmail' && (
          <div className="animate-[fade-in_0.3s_ease-out]">
            {!sessionId ? (
              // Not logged in - show login prompt
              <div className="card p-8 text-center">
                <div className="max-w-md mx-auto">
                  <div className="w-16 h-16 mx-auto mb-6 rounded-full bg-gradient-to-br from-cyan-500/20 to-blue-500/20 flex items-center justify-center">
                    <InboxIcon />
                  </div>
                  <h2 className="text-xl font-semibold text-white mb-3">
                    Connect Your Gmail
                  </h2>
                  <p className="text-slate-400 mb-6">
                    Securely connect your Gmail account to analyze emails directly from your inbox. 
                    We only request read access and never store your email content.
                  </p>
                  <button
                    onClick={handleGoogleLogin}
                    className="btn bg-white text-slate-800 hover:bg-slate-100 font-medium shadow-lg hover:shadow-xl transition-all"
                  >
                    <GoogleIcon />
                    <span>Continue with Google</span>
                  </button>
                  {gmailError && (
                    <div className="error-message mt-4 text-left">
                      {gmailError}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              // Logged in - show Gmail content
              <div className="space-y-6">
                {/* Header with user info */}
                <div className="card p-4 flex flex-wrap items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-500 to-blue-500 flex items-center justify-center text-white font-semibold">
                      {(userInfo?.name || userInfo?.email || 'U').charAt(0).toUpperCase()}
                    </div>
                    <div>
                      <div className="font-medium text-white">
                        {userInfo?.name || 'Connected User'}
                      </div>
                      {userInfo?.email && (
                        <div className="text-sm text-slate-400">
                          {userInfo.email}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={fetchGmailThreads}
                      disabled={gmailLoading}
                      className="btn btn-secondary"
                    >
                      <RefreshIcon spinning={gmailLoading} />
                      <span>{gmailLoading ? 'Refreshing...' : 'Refresh'}</span>
                    </button>
                    <button
                      onClick={handleLogout}
                      className="btn btn-danger"
                    >
                      <LogoutIcon />
                      <span>Logout</span>
                    </button>
                  </div>
                </div>

                {/* Error display */}
                {gmailError && (
                  <div className="error-message">
                    {gmailError}
                  </div>
                )}

                {/* Loading state */}
                {gmailLoading && gmailThreads.length === 0 && (
                  <div className="card p-12 text-center">
                    <LoadingSpinner />
                    <p className="text-slate-400 mt-4">Loading your Gmail threads...</p>
                  </div>
                )}

                {/* Empty state */}
                {!gmailLoading && gmailThreads.length === 0 && !gmailError && (
                  <div className="card p-12 text-center border-dashed">
                    <InboxIcon />
                    <p className="text-slate-400 mt-4">
                      No threads found. Click Refresh to load your inbox.
                    </p>
                  </div>
                )}

                {/* Thread list */}
                {gmailThreads.length > 0 && (
                  <GmailThreadList
                    threads={gmailThreads}
                    onAnalyze={handleAnalyzeGmailThread}
                    analyzingThreadId={analyzingThreadId}
                    analysisResults={analysisResults}
                    analysisError={analysisError}
                  />
                )}
              </div>
            )}
          </div>
        )}

        {/* Footer */}
        <footer className="mt-12 pt-8 border-t border-slate-800 text-center">
          <p className="text-slate-500 text-sm">
            SeamSecure uses AI to analyze email patterns and detect potential phishing attempts.
            <br />
            Always verify suspicious emails through official channels.
          </p>
        </footer>
      </div>
    </div>
  );
}

export default App;
