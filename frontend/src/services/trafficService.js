import { fetchApi } from "../utils/api";

export async function analyzeTrafficFlow(sourceIp, destinationIp, protocol, userId = "") {
  try {
    const res = await fetchApi("/api/traffic-analysis/analyze", {
      method: "POST",
      body: JSON.stringify({
        source_ip: sourceIp,
        destination_ip: destinationIp,
        protocol: protocol,
        user_id: userId
      }),
    });

    const dataObj = res?.data || res || {};
    const newRecord = res?.new_record || dataObj.new_record || {};

    return {
      id: newRecord.id || dataObj.id,
      timestamp: newRecord.timestamp || dataObj.timestamp || new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC",
      source_ip: newRecord.source_ip || sourceIp,
      destination_ip: newRecord.destination_ip || destinationIp,
      source: newRecord.source_ip || sourceIp,
      destination: newRecord.destination_ip || destinationIp,
      protocol: newRecord.protocol || protocol,
      flow_direction: newRecord.flow_direction || "Upstream (Outbound)",
      flow: newRecord.flow_direction || "Upstream (Outbound)",
      packets: newRecord.packets || `${dataObj.total_packets || 0} Packets`,
      bandwidth: newRecord.bandwidth || `${dataObj.bandwidth || 0} Mbps`,
      size_bytes: newRecord.size_bytes || dataObj.size_bytes || 512,
      abuse_score: newRecord.abuse_score || newRecord.abuseipdb_score || dataObj.abuseipdb_score || `${dataObj.abuse_score || 0}% Risk`,
      abuseipdb_score: newRecord.abuseipdb_score || newRecord.abuse_score || `${dataObj.abuse_score || 0}% Risk`,
      score: newRecord.abuse_score || newRecord.abuseipdb_score || dataObj.abuseipdb_score || `${dataObj.abuse_score || 0}% Risk`,
      threat_score: newRecord.threat_score ?? dataObj.threat_score ?? 0.15,
      risk_status: newRecord.risk_status || newRecord.status || dataObj.status || "SAFE (Clean Flow)",
      status: newRecord.risk_status || newRecord.status || dataObj.status || "SAFE (Clean Flow)",
      flag_status: newRecord.flag_status || "SAFE",
      rawResponse: res
    };
  } catch (error) {
    console.warn("Async exception in analyzeTrafficFlow:", error);
    return null;
  }
}

