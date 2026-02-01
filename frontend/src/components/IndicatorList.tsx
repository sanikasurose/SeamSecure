// Import the RiskIndicator type from the API types.
// This ensures type safety for the indicators prop.
import { RiskIndicator } from "../types/api";

// Component to display a list of risk indicators.
export function IndicatorList({ indicators }: { indicators: RiskIndicator[] }) {

    // Handle the case where there are no indicators to display.
  if (indicators.length === 0) {
    return <p>No risk indicators detected.</p>;
  }

  // Render the list of indicators with their type, severity, and description.
  return (
    <ul>
      {indicators.map((ind, i) => (
        <li key={i}>
          <strong>{ind.type}</strong> ({ind.severity}): {ind.description}
        </li>
      ))}
    </ul>
  );
}
