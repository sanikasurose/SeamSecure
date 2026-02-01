/**
 * Import the RiskLevel type from the API types.
 * TypeScript will ensure that only valid risk levels can be passed to this component.
 */ 
import { RiskLevel } from "../types/api";

// Map risk levels to colors for display purposes.
// This helps users quickly identify the severity of the risk.
const colors: Record<RiskLevel, string> = {
  safe: "green",
  suspicious: "orange",
  dangerous: "red",
};

// The RiskBadge component displays a colored badge based on the risk level.
export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span style={{ color: colors[level], fontWeight: "bold" }}>
      {level.toUpperCase()}
    </span>
  );
}
