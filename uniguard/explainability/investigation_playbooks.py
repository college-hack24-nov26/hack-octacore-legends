"""Defensive SOC Analyst Investigation Playbooks.

Provides safe, actionable, and defensive next-step investigation procedures
tailored to each classified threat category.
"""

from typing import Dict, List


class DefensiveInvestigationPlaybooks:
    """Actionable, defensive investigation suggestions for security analysts."""

    PLAYBOOKS: Dict[str, List[str]] = {
        "PORT_SCAN": [
            "Review destination port diversity: Check how many distinct ports were probed and whether well-known services (21, 22, 23, 80, 443, 3389) were targeted.",
            "Verify source identity: Correlate the source IP against authorized internal vulnerability assessment scanners (e.g. Nessus, Qualys) or asset inventories.",
            "Review related events: Query recent historical events from this source IP to assess horizontal scan breadth across internal subnets.",
            "Defensive staging: Stage the source IP for temporary rate-limiting or firewall access-control list (ACL) candidate review.",
            "Host log audit: Check authentication and firewall logs on the destination hosts for subsequent brute-force or exploit attempts.",
        ],
        "SYN_FLOOD": [
            "Inspect target host TCP table: Query destination host connection states to check for an abnormal backlog in the SYN_RECV state.",
            "Verify SYN cookie defense: Ensure kernel SYN cookies (tcp_syncookies) are enabled and operational on the target server operating system.",
            "Ingress rate limiting: Review boundary switch/router ACLs to apply ingress SYN rate-limiting for the affected service port.",
            "Audit spoofed sources: Examine whether source IP addresses belong to unroutable, reserved (RFC 1918/RFC 5735), or bogon ranges indicating spoofing.",
            "Upstream DDoS protection: If volume exceeds network link capacity, activate upstream ISP scrubbing or DDoS mitigation profiles.",
        ],
        "UDP_FLOOD": [
            "Target port verification: Determine whether the destination UDP port hosts an intended public service (e.g. DNS 53, NTP 123) or arbitrary unmapped ports.",
            "Amplification risk check: Verify that the destination host does not respond with amplified payloads that could reflect traffic elsewhere.",
            "Perimeter UDP rate-limiting: Restrict ingress UDP packet rate on edge firewalls to mitigate bandwidth saturation.",
            "Engage upstream mitigation: Coordinate with transit providers if wire rates approach edge interface saturation.",
        ],
        "SLOWLORIS": [
            "Inspect HTTP connection table: Identify open HTTP/HTTPS connections holding persistent sockets with uncompleted request headers.",
            "Web worker pool check: Monitor web server worker thread pool saturation (e.g., Apache MaxRequestWorkers or Nginx worker_connections).",
            "Configure aggressive timeouts: Ensure minimal request header read timeouts (e.g., RequestReadTimeout in Apache) are enforced on the origin.",
            "Reverse proxy offloading: Deploy or verify an edge reverse proxy (e.g., Cloudflare, HAProxy, AWS ALB) to absorb slow client handshakes before reaching origin.",
        ],
        "DATA_EXFILTRATION": [
            "Examine outbound byte volume: Quantify total bytes transmitted outbound and verify transfer duration and timestamp relative to normal operational hours.",
            "Destination reputation & ASN: Check the external destination IP against threat intelligence feeds, ASN registries, and geolocation lookups.",
            "Endpoint process correlation: Inspect endpoint telemetry (EDR/Sysmon) on the source host to identify the process and user context responsible for the transfer.",
            "Data sensitivity assessment: Review whether sensitive enterprise data, database dumps, or confidential files were accessed prior to the egress flow.",
            "Incident escalation: If unauthorized egress is confirmed, initiate CSIRT triage protocol and isolate the compromised source host.",
        ],
        "C2_BEACON": [
            "Beacon cadence analysis: Review packet inter-arrival times to identify regular or jittered periodic communication intervals.",
            "Domain & IP reputation: Query DNS resolution history and external threat intelligence for the target command-and-control destination.",
            "Host forensic triage: Review endpoint process execution history, scheduled tasks, and persistence mechanisms on the internal source host.",
            "Network containment: Implement a temporary DNS sinkhole or firewall drop rule for the destination IP/domain pending host isolation.",
        ],
        "ANOMALOUS": [
            "Baseline comparison: Contrast observed flow entropy, packet length distribution, and rates against normal traffic profiles for the target service.",
            "Sensor visibility review: Check whether asymmetric routing or tap filter constraints prevented capture of reverse packets.",
            "Cross-correlation: Monitor for secondary alerts or lateral movement attempts from the same source endpoint before taking disruptive actions.",
            "Passive observation: Retain packet flow telemetry in the SOC event history for longitudinal behavioral analysis.",
        ],
        "BENIGN": [
            "Standard monitoring: Traffic characteristics conform to normal baseline behavior; no immediate containment action is required.",
            "Baseline validation: Ensure this observed pattern accurately represents authorized enterprise application traffic.",
            "Defensive note: Benign classification reflects current model and signature evaluations; continued network visibility remains essential.",
        ],
    }

    @classmethod
    def get_suggestions(cls, threat_category: str) -> List[str]:
        """Returns defensive investigation steps for the given threat category."""
        key = threat_category.upper().replace(" ", "_")
        return cls.PLAYBOOKS.get(key, cls.PLAYBOOKS["ANOMALOUS"])
