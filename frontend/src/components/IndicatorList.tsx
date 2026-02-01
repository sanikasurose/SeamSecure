import React from 'react';
import { RiskIndicator, Severity } from '../types/api';

/**
 * Props interface for the IndicatorList component.
 */
interface IndicatorListProps {
  indicators: RiskIndicator[];
}

/**
 * Icon components for severity levels
 */
const InfoIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" />
    <line x1="12" y1="16" x2="12" y2="12" />
    <line x1="12" y1="8" x2="12.01" y2="8" />
  </svg>
);

const WarningIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);

const AlertIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
    <line x1="12" y1="8" x2="12" y2="12" />
    <line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
);

/**
 * Severity configuration
 */
const severityConfig: Record<Severity, {
  className: string;
  badgeClass: string;
  Icon: React.ComponentType;
  borderClass: string;
}> = {
  low: {
    className: 'text-blue-400',
    badgeClass: 'severity-low',
    Icon: InfoIcon,
    borderClass: 'border-l-blue-500/50',
  },
  medium: {
    className: 'text-amber-400',
    badgeClass: 'severity-medium',
    Icon: WarningIcon,
    borderClass: 'border-l-amber-500/50',
  },
  high: {
    className: 'text-red-400',
    badgeClass: 'severity-high',
    Icon: AlertIcon,
    borderClass: 'border-l-red-500/50',
  },
};

/**
 * Formats an indicator type string into a human-readable title.
 * Converts snake_case to Title Case (e.g., "urgency_language" → "Urgency Language").
 */
function formatIndicatorType(type: string): string {
  return type
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
}

/**
 * IndicatorList displays a styled list of risk indicators.
 * Features:
 * - Color-coded severity with left border accent
 * - Icons for each severity level
 * - Card-like styling with hover effects
 * - Smooth animations on appearance
 * - Empty state message when no indicators exist
 */
export function IndicatorList({ indicators }: IndicatorListProps) {
  // Handle the case where there are no indicators to display.
  if (indicators.length === 0) {
    return (
      <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-4 text-center">
        <div className="flex items-center justify-center gap-2 text-emerald-400">
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
          <span className="font-medium">No risk indicators detected</span>
        </div>
        <p className="text-slate-400 text-sm mt-1">
          This email thread appears to be safe.
        </p>
      </div>
    );
  }

  return (
    <ul className="space-y-3">
      {indicators.map((indicator, index) => {
        const config = severityConfig[indicator.severity];
        const Icon = config.Icon;

        return (
          <li
            key={index}
            className={`
              bg-slate-900/50 rounded-lg p-4 border border-slate-700/50
              border-l-4 ${config.borderClass}
              transition-all duration-200 hover:bg-slate-900/70
              animate-[slide-up_0.3s_ease-out]
            `}
            style={{ animationDelay: `${index * 50}ms`, animationFillMode: 'both' }}
          >
            <div className="flex items-start gap-3">
              {/* Severity icon */}
              <div className={`flex-shrink-0 mt-0.5 ${config.className}`}>
                <Icon />
              </div>
              
              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <span className="font-semibold text-white text-sm">
                    {formatIndicatorType(indicator.type)}
                  </span>
                  <span className={`badge ${config.badgeClass} text-[10px] py-0.5 px-2`}>
                    {indicator.severity}
                  </span>
                </div>
                <p className="text-slate-400 text-sm leading-relaxed">
                  {indicator.description}
                </p>
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
