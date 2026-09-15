import os
import asyncio
import logging
from typing import Optional, Dict, Any

try:
    from app.services.threat_intelligence import threat_service
except ImportError:
    from backend.app.services.threat_intelligence import threat_service

logger = logging.getLogger("netshield_sniffer")

class PrivacySafeSniffer:
    """
    Privacy-focused network packet sniffer using Scapy.
    Extracts L3/L4 header metadata only (source/destination IP, protocol, port).
    Completely discards packet payloads, raw bytes, and message contents.
    Filters private IP addresses and queries AbuseIPDB for public destination IPs.
    """
    def __init__(self):
        self.is_running = False

    def is_private_ip(self, ip_str: str) -> bool:
        """Filter out internal / local loopback IP addresses."""
        if not ip_str or not isinstance(ip_str, str):
            return True
        clean_ip = ip_str.strip()
        private_prefixes = (
            "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
            "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
            "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
            "0.0.0.0", "::1", "fe80:"
        )
        return clean_ip.startswith(private_prefixes)

    def extract_header_metadata(self, packet) -> Optional[Dict[str, Any]]:
        """
        PRIVACY GUARANTEE:
        - Extracts ONLY Layer 3/4 headers (IP & Port).
        - Discards packet payloads, raw bytes, and message contents.
        - Stores nothing on disk.
        """
        try:
            from scapy.all import IP, TCP, UDP
        except Exception:
            return None

        if not packet.haslayer(IP):
            return None

        # Extract Header IP metadata ONLY
        src_ip = str(packet[IP].src)
        dst_ip = str(packet[IP].dst)

        # Skip local/internal traffic
        if self.is_private_ip(dst_ip):
            return None

        # Determine protocol
        protocol = "OTHER"
        dest_port = None
        if packet.haslayer(TCP):
            protocol = "TCP"
            dest_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            dest_port = int(packet[UDP].dport)

        # Return header metadata tuple (No payload data included)
        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "port": dest_port
        }

    def process_packet(self, packet):
        metadata = self.extract_header_metadata(packet)
        if metadata:
            dst_ip = metadata["destination_ip"]
            logger.info(f"[Sniffer] Outbound packet detected to: {dst_ip} ({metadata['protocol']}:{metadata['port']})")

            # Fire an asynchronous call to AbuseIPDB via your Threat Intelligence Service
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(threat_service.check_ip_reputation(dst_ip))
                else:
                    asyncio.run(threat_service.check_ip_reputation(dst_ip))
            except Exception as err:
                logger.warning(f"[Sniffer] Warning: Could not dispatch threat lookup: {err}")

    def start_sniffing(self, packet_count: int = 10, timeout: Optional[int] = 10, interface: Optional[str] = None):
        """
        Runs packet capturing strictly in RAM (store=False).
        """
        logger.info("[Sniffer] Starting privacy-safe network inspection...")
        self.is_running = True
        try:
            from scapy.all import sniff
            kwargs = {
                "prn": self.process_packet,
                "store": False,  # CRITICAL: Do not keep packets in memory or disk
                "count": packet_count,
                "filter": "ip"
            }
            if timeout:
                kwargs["timeout"] = timeout
            if interface:
                kwargs["iface"] = interface

            try:
                sniff(**kwargs)
            except Exception as capture_err:
                err_str = str(capture_err).lower()
                if "winpcap" in err_str or "layer 2" in err_str:
                    logger.info("[Sniffer] WinPcap/Npcap not available, attempting Layer 3 socket capture fallback...")
                    from scapy.config import conf
                    kwargs["L2socket"] = conf.L3socket
                    sniff(**kwargs)
                else:
                    raise capture_err
        except Exception as e:
            logger.warning(f"[Sniffer] Packet capture completed or notice: {e}")
        finally:
            self.is_running = False
            logger.info("[Sniffer] Inspection finished.")


safe_sniffer = PrivacySafeSniffer()
