import IncidentQueueTable from "../../../components/analyst/IncidentQueueTable";
import ErrorBoundary from "../../../components/ErrorBoundary";

export const metadata = {
  title: "Incident Queue | Security Analyst | NetShield-AI",
};

export default function AnalystIncidentsPage() {
  return (
    <div style={{ padding: "0.5rem" }}>
      <ErrorBoundary>
        <IncidentQueueTable embedded={false} />
      </ErrorBoundary>
    </div>
  );
}

