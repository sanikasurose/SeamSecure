import React from 'react';
import { GmailThread, ThreadResponse } from '../types/api';
import { RiskBadge } from './RiskBadge';
import { IndicatorList } from './IndicatorList';

/**
 * Props interface for the GmailThreadList component.
 */
interface GmailThreadListProps {
  threads: GmailThread[];
  onAnalyze: (threadId: string) => void;
  analyzingThreadId: string | null;
  analysisResults: Record<string, ThreadResponse>;
  analysisError: string | null;
}

/**
 * Icon components
 */
const AnalyzeIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);

const RefreshIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
    <path d="M21 3v5h-5" />
  </svg>
);

const LoadingSpinner = () => (
  <svg className="w-4 h-4 spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10" strokeOpacity="0.25" />
    <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" />
  </svg>
);

const ChevronDownIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="6 9 12 15 18 9" />
  </svg>
);

const MailIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="16" rx="2" />
    <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
  </svg>
);

const ClockIcon = () => (
  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" />
    <polyline points="12 6 12 12 16 14" />
  </svg>
);

const MessagesIcon = () => (
  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
  </svg>
);

/**
 * Formats a date string into a more readable format.
 */
function formatDate(dateString: string): string {
  try {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    
    // If today, show time only
    if (diffDays === 0) {
      return date.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });
    }
    
    // If yesterday
    if (diffDays === 1) {
      return 'Yesterday';
    }
    
    // If within a week
    if (diffDays < 7) {
      return date.toLocaleDateString('en-US', { weekday: 'short' });
    }
    
    // Otherwise show date
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return dateString;
  }
}

/**
 * Truncates a string to a maximum length with ellipsis.
 */
function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

/**
 * GmailThreadList displays a list of Gmail threads with analyze functionality.
 */
export function GmailThreadList({
  threads,
  onAnalyze,
  analyzingThreadId,
  analysisResults,
  analysisError,
}: GmailThreadListProps) {
  if (threads.length === 0) {
    return (
      <div className="card p-12 text-center border-dashed">
        <div className="text-slate-500 mb-2">
          <MailIcon />
        </div>
        <p className="text-slate-400">No threads found in your inbox.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {threads.map((thread, index) => {
        const isAnalyzing = analyzingThreadId === thread.id;
        const result = analysisResults[thread.id];
        const showError = analysisError && analyzingThreadId === thread.id;

        return (
          <div
            key={thread.id}
            className={`
              card overflow-hidden
              animate-[slide-up_0.3s_ease-out]
              ${result ? (
                result.risk_level === 'safe' ? 'border-emerald-500/20' :
                result.risk_level === 'suspicious' ? 'border-amber-500/20' :
                'border-red-500/20'
              ) : ''}
            `}
            style={{ animationDelay: `${index * 50}ms`, animationFillMode: 'both' }}
          >
            {/* Thread Header */}
            <div className="p-4">
              <div className="flex items-start justify-between gap-4">
                {/* Thread Info */}
                <div className="flex-1 min-w-0">
                  {/* Sender & Date Row */}
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="font-semibold text-white text-sm truncate">
                      {truncate(thread.from, 40)}
                    </span>
                    <div className="flex items-center gap-1.5 text-slate-500 text-xs flex-shrink-0">
                      <ClockIcon />
                      <span>{formatDate(thread.date)}</span>
                    </div>
                  </div>
                  
                  {/* Subject */}
                  <p className="text-slate-300 text-sm mb-2 line-clamp-2">
                    {thread.subject || '(No subject)'}
                  </p>
                  
                  {/* Meta info */}
                  <div className="flex items-center gap-3 text-xs text-slate-500">
                    <div className="flex items-center gap-1.5">
                      <MessagesIcon />
                      <span>
                        {thread.message_count} message{thread.message_count !== 1 ? 's' : ''}
                      </span>
                    </div>
                    {result && (
                      <RiskBadge level={result.risk_level} size="sm" />
                    )}
                  </div>
                </div>

                {/* Analyze Button */}
                <button
                  onClick={() => onAnalyze(thread.id)}
                  disabled={isAnalyzing}
                  className={`
                    btn flex-shrink-0
                    ${isAnalyzing 
                      ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                      : result
                        ? 'btn-secondary'
                        : 'btn-primary'
                    }
                  `}
                >
                  {isAnalyzing ? (
                    <>
                      <LoadingSpinner />
                      <span>Analyzing...</span>
                    </>
                  ) : result ? (
                    <>
                      <RefreshIcon />
                      <span>Re-analyze</span>
                    </>
                  ) : (
                    <>
                      <AnalyzeIcon />
                      <span>Analyze</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Error display for this thread */}
            {showError && (
              <div className="px-4 pb-4">
                <div className="error-message text-sm">
                  {analysisError}
                </div>
              </div>
            )}

            {/* Analysis Results - Expandable Section */}
            {result && (
              <div className="border-t border-slate-700/50 bg-slate-900/30">
                <div className="p-4 space-y-4">
                  {/* Risk Score Progress Bar */}
                  <div className="flex items-center gap-4">
                    <div className="flex-1">
                      <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                        <span>Risk Score</span>
                        <span className={`font-semibold ${
                          result.risk_level === 'safe' ? 'text-emerald-400' :
                          result.risk_level === 'suspicious' ? 'text-amber-400' :
                          'text-red-400'
                        }`}>
                          {Math.round(result.risk_score * 100)}%
                        </span>
                      </div>
                      <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-700 ease-out ${
                            result.risk_level === 'safe' ? 'bg-emerald-500' :
                            result.risk_level === 'suspicious' ? 'bg-amber-500' :
                            'bg-red-500'
                          }`}
                          style={{ width: `${result.risk_score * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Summary */}
                  <div>
                    <h4 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
                      Summary
                    </h4>
                    <p className="text-slate-300 text-sm leading-relaxed">
                      {result.summary}
                    </p>
                  </div>

                  {/* Indicators */}
                  <div>
                    <h4 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
                      Risk Indicators
                    </h4>
                    <IndicatorList indicators={result.indicators} />
                  </div>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
