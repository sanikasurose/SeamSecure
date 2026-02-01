import React from 'react';
import { RiskLevel } from '../types/api';

/**
 * Props interface for the RiskBadge component.
 */
interface RiskBadgeProps {
  level: RiskLevel;
  showIcon?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

/**
 * Icon components for each risk level
 */
const SafeIcon = () => (
  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
    <polyline points="22 4 12 14.01 9 11.01" />
  </svg>
);

const SuspiciousIcon = () => (
  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);

const DangerousIcon = () => (
  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" />
    <line x1="15" y1="9" x2="9" y2="15" />
    <line x1="9" y1="9" x2="15" y2="15" />
  </svg>
);

/**
 * Badge configuration for each risk level
 */
const badgeConfig: Record<RiskLevel, { 
  className: string; 
  Icon: React.ComponentType;
  label: string;
}> = {
  safe: {
    className: 'badge-safe',
    Icon: SafeIcon,
    label: 'Safe',
  },
  suspicious: {
    className: 'badge-suspicious',
    Icon: SuspiciousIcon,
    label: 'Suspicious',
  },
  dangerous: {
    className: 'badge-dangerous',
    Icon: DangerousIcon,
    label: 'Dangerous',
  },
};

/**
 * Size configuration
 */
const sizeConfig = {
  sm: 'text-xs py-1 px-2',
  md: 'text-xs py-1.5 px-3',
  lg: 'text-sm py-2 px-4',
};

/**
 * RiskBadge displays a pill-shaped badge indicating the risk level.
 * Features:
 * - Color-coded backgrounds with matching text
 * - Optional icon for visual reinforcement
 * - Multiple size variants
 * - Smooth hover animation
 */
export function RiskBadge({ level, showIcon = true, size = 'md' }: RiskBadgeProps) {
  const { className, Icon, label } = badgeConfig[level];
  const sizeClass = sizeConfig[size];

  return (
    <span 
      className={`badge ${className} ${sizeClass} transition-transform hover:scale-105`}
      role="status"
      aria-label={`Risk level: ${label}`}
    >
      {showIcon && <Icon />}
      <span>{label}</span>
    </span>
  );
}
