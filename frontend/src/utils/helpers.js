export function parseLogItem(log) {
  if (!log) return { timestamp: "N/A", sourceIp: "N/A", destIp: "N/A", proto: "TCP", size: "N/A", score: 0, status: "Normal" };

  const timestamp =
    log.timestamp ||
    log.time ||
    log.datetime ||
    (log["Flow Duration"] !== undefined ? `Flow-${log["Flow Duration"]}ms` : "11:42:00 UTC");

  const sourceIp = log.src_port
    ? `${log.source_ip || log.src || "192.168.1.50"}:${log.src_port}`
    : log.source_ip ||
      log.src ||
      log.source ||
      log["Source IP"] ||
      "192.168.1.50";

  const destIp = log.dst_port
    ? `${log.destination_ip || log.dst || "10.0.0.5"}:${log.dst_port}`
    : log.destination_ip ||
      log.dst ||
      log.destination ||
      (log["Destination Port"] !== undefined ? `10.0.0.1:${log["Destination Port"]}` : "10.0.0.5");

  const proto = log.protocol || log.proto || "TCP";

  const rawSize =
    log.packet_size !== undefined
      ? log.packet_size
      : log.size !== undefined
      ? log.size
      : log.length !== undefined
      ? log.length
      : log["Average Packet Size"] !== undefined
      ? Math.round(log["Average Packet Size"])
      : log["Total Length of Fwd Packets"] !== undefined
      ? log["Total Length of Fwd Packets"]
      : "N/A";

  const size = typeof rawSize === "number" ? `${rawSize} B` : String(rawSize);

  const score =
    log.threat_score !== undefined
      ? log.threat_score
      : log.score !== undefined
      ? log.score
      : log.Label && log.Label !== "BENIGN"
      ? 92
      : 15;

  const status =
    log.detection_status ||
    log.status ||
    (log.Label && log.Label !== "BENIGN" ? "Critical" : score > 80 ? "Critical" : "Normal");

  return { timestamp, sourceIp, destIp, proto, size, score, status };
}
