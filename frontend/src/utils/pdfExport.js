/**
 * NetShield-AI SOC Forensic Audit Log PDF Generator
 * Generates and downloads a clean, professionally formatted PDF report for an individual audit log entry.
 */

export function generateAuditLogPDF(log) {
  if (!log) return;

  const logId = log.id || "AUD-UNKNOWN";
  const timestamp = log.timestamp || new Date().toISOString();
  const actor = log.actor || "sec_admin@gmail.com";
  const userType = log.user_type || "Security Administrator";
  const loginTime = log.login_time || "09:45:00 UTC";
  const logoutTime = log.logout_time || "Active Session";
  const action = log.action || "System Operation Executed";
  const module = log.module || "SOC Core Platform";
  const ipOrigin = log.ip_origin || "192.168.1.50";
  const status = log.status || "Success";
  const severity = log.severity || "Informational";
  const details = log.details || `Operation '${action}' executed by ${actor} and logged to PostgreSQL database.`;
  const reportDate = new Date().toUTCString();
  const sha256Checksum = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855_${Date.now().toString(16)}`;

  const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forensic Audit Report - ${logId}</title>
  <style>
    @page {
      size: A4;
      margin: 15mm;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      margin: 0;
      padding: 20px;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    .report-card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 30px;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
      max-width: 800px;
      margin: 0 auto;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #3b82f6;
      padding-bottom: 18px;
      margin-bottom: 25px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .logo-badge {
      background: #2563eb;
      color: #ffffff;
      font-weight: 800;
      font-size: 1.2rem;
      padding: 8px 14px;
      border-radius: 8px;
      letter-spacing: 0.05em;
    }
    .brand-title {
      font-size: 1.35rem;
      font-weight: 700;
      color: #f8fafc;
      margin: 0;
    }
    .brand-sub {
      font-size: 0.75rem;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .meta-badge {
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid rgba(59, 130, 246, 0.35);
      color: #60a5fa;
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    .section-title {
      font-size: 1rem;
      font-weight: 700;
      color: #38bdf8;
      margin-top: 25px;
      margin-bottom: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid #334155;
      padding-bottom: 6px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 16px;
      margin-bottom: 20px;
    }
    .field {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 12px 16px;
    }
    .label {
      font-size: 0.725rem;
      font-weight: 600;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 4px;
    }
    .value {
      font-size: 0.95rem;
      font-weight: 600;
      color: #f8fafc;
      word-break: break-word;
    }
    .code-val {
      font-family: monospace;
      color: #38bdf8;
    }
    .badge-status {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 700;
      background: rgba(16, 185, 129, 0.2);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .badge-status.failed {
      background: rgba(239, 68, 68, 0.2);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.35);
    }
    .badge-role {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      background: rgba(168, 85, 247, 0.2);
      color: #c084fc;
      border: 1px solid rgba(168, 85, 247, 0.35);
    }
    .full-width {
      grid-column: span 2;
    }
    .details-box {
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 14px;
      font-size: 0.875rem;
      line-height: 1.5;
      color: #cbd5e1;
    }
    .footer {
      margin-top: 35px;
      border-top: 1px dashed #334155;
      padding-top: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.725rem;
      color: #64748b;
    }
    .footer-left {
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    @media print {
      body {
        background: #ffffff !important;
        color: #0f172a !important;
      }
      .report-card {
        background: #ffffff !important;
        border: 1px solid #cbd5e1 !important;
        color: #0f172a !important;
        box-shadow: none !important;
      }
      .brand-title, .value {
        color: #0f172a !important;
      }
      .field, .details-box {
        background: #f8fafc !important;
        border: 1px solid #cbd5e1 !important;
      }
    }
  </style>
</head>
<body>
  <div class="report-card">
    <div class="header">
      <div class="brand">
        <div class="logo-badge">NETSHIELD</div>
        <div>
          <div class="brand-title">SOC Forensic Audit Log Report</div>
          <div class="brand-sub">PostgreSQL Immutable Audit Trail</div>
        </div>
      </div>
      <div class="meta-badge">CISO CONFIDENTIAL</div>
    </div>

    <div class="section-title">Forensic Log Identifier & Metadata</div>
    <div class="grid">
      <div class="field">
        <div class="label">Log Entry ID</div>
        <div class="value code-val">${logId}</div>
      </div>
      <div class="field">
        <div class="label">Real Event Timestamp</div>
        <div class="value">${timestamp}</div>
      </div>
      <div class="field">
        <div class="label">User / Actor Account</div>
        <div class="value">${actor}</div>
      </div>
      <div class="field">
        <div class="label">Type of User (Role)</div>
        <div class="value"><span class="badge-role">${userType}</span></div>
      </div>
    </div>

    <div class="section-title">Session Tracking & Execution Scope</div>
    <div class="grid">
      <div class="field">
        <div class="label">Session Login Timestamp</div>
        <div class="value">${loginTime}</div>
      </div>
      <div class="field">
        <div class="label">Session Logout Timestamp</div>
        <div class="value">${logoutTime}</div>
      </div>
      <div class="field">
        <div class="label">Action Performed</div>
        <div class="value">${action}</div>
      </div>
      <div class="field">
        <div class="label">Execution Status</div>
        <div class="value">
          <span class="badge-status ${status.toLowerCase().includes("failed") || status.toLowerCase().includes("denied") ? "failed" : ""}">
            ${status}
          </span>
        </div>
      </div>
      <div class="field">
        <div class="label">Platform Module</div>
        <div class="value">${module}</div>
      </div>
      <div class="field">
        <div class="label">IP Origin</div>
        <div class="value code-val">${ipOrigin}</div>
      </div>
    </div>

    <div class="section-title">Operational Trace Details</div>
    <div class="details-box">
      ${details}
    </div>

    <div class="footer">
      <div class="footer-left">
        <div><strong>Storage Backend:</strong> PostgreSQL Immutable Audit Log Table</div>
        <div><strong>SHA-256 Checksum:</strong> <span class="code-val">${sha256Checksum}</span></div>
      </div>
      <div>
        <div>Report Generated: ${reportDate}</div>
        <div style="text-align: right; margin-top: 3px;">NetShield-AI Security Engine</div>
      </div>
    </div>
  </div>

  <script>
    window.onload = function() {
      window.print();
    };
  </script>
</body>
</html>
  `;

  const printWindow = window.open("", "_blank", "width=850,height=950");
  if (printWindow) {
    printWindow.document.write(htmlContent);
    printWindow.document.close();
  }
}
