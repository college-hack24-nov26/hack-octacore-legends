"""Local Endpoint Discovery and Network Boundary Registry.

Discovers and caches local IP addresses (IPv4 & IPv6) across physical NICs,
VPN adapters, and virtual interfaces (Docker, WSL, Hyper-V) with zero per-packet
operating system overhead.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from typing import Set, List, Optional, Dict, Any
from enum import Enum
import psutil


class EndpointRole(Enum):
    """Directional role of an IP endpoint relative to the monitored host/enclave."""
    LOCAL_INBOUND = "LOCAL_INBOUND"     # Remote -> Local
    LOCAL_OUTBOUND = "LOCAL_OUTBOUND"   # Local -> Remote
    INTERNAL_LAN = "INTERNAL_LAN"       # Local -> Local
    EXTERNAL_TRANSIT = "EXTERNAL_TRANSIT" # Remote -> Remote (e.g. inline tap)


class LocalEndpointRegistry:
    """High-performance thread-safe registry of local IP endpoints with O(1) lookup."""

    _instance: Optional[LocalEndpointRegistry] = None
    _lock = threading.Lock()

    def __init__(
        self,
        manual_subnets: Optional[List[str]] = None,
        auto_discover: bool = True,
        refresh_interval_sec: float = 60.0,
    ) -> None:
        self.manual_subnets = manual_subnets or []
        self.auto_discover = auto_discover
        self.refresh_interval_sec = refresh_interval_sec

        self._local_ips: Set[str] = set()
        self._local_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._last_refresh_time: float = 0.0
        self._registry_lock = threading.RLock()

        # Parse manual subnets if provided
        for subnet_str in self.manual_subnets:
            try:
                net = ipaddress.ip_network(subnet_str.strip(), strict=False)
                self._local_networks.append(net)
            except ValueError:
                pass

        if self.auto_discover:
            self.refresh()

    @classmethod
    def get_instance(cls) -> LocalEndpointRegistry:
        """Singleton accessor for global registry sharing."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def refresh(self) -> None:
        """Scans network adapters and refreshes local IP cache."""
        with self._registry_lock:
            discovered_ips: Set[str] = set()
            discovered_nets: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = list(self._local_networks)

            try:
                adapters = psutil.net_if_addrs()
                for iface_name, addrs in adapters.items():
                    # Process each interface
                    for addr in addrs:
                        # Family AF_INET (IPv4) or AF_INET6 (IPv6)
                        if addr.family.name in ("AF_INET", "AF_INET6"):
                            ip_str = addr.address
                            # Strip zone ID for IPv6 (e.g. fe80::1%eth0)
                            if "%" in ip_str:
                                ip_str = ip_str.split("%")[0]

                            try:
                                ip_obj = ipaddress.ip_address(ip_str)
                            except ValueError:
                                continue

                            # Strictly exclude loopback
                            if ip_obj.is_loopback:
                                continue

                            # Strictly exclude multicast & unspecified
                            if ip_obj.is_multicast or ip_obj.is_unspecified:
                                continue

                            # Add IP directly
                            discovered_ips.add(str(ip_obj))

                            # If netmask is present, add the local network
                            if addr.netmask:
                                mask_str = addr.netmask
                                if "%" in mask_str:
                                    mask_str = mask_str.split("%")[0]
                                try:
                                    net = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
                                    discovered_nets.append(net)
                                except ValueError:
                                    pass

            except Exception:
                pass

            self._local_ips = discovered_ips
            self._local_networks = discovered_nets
            self._last_refresh_time = time.time()

    def is_local_ip(self, ip_str: str) -> bool:
        """O(1) fast-path check to determine if an IP address belongs to the local machine/network."""
        # 1. Exact string match against cached local adapter IPs (O(1) hash lookup)
        if ip_str in self._local_ips:
            return True

        # Quick check if refresh is due
        now = time.time()
        if self.auto_discover and (now - self._last_refresh_time) > self.refresh_interval_sec:
            self.refresh()
            if ip_str in self._local_ips:
                return True

        # 2. Check if IP falls within configured local subnets
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback:
                return False
            for net in self._local_networks:
                if ip_obj in net:
                    return True
        except ValueError:
            return False

        return False

    def register_manual_ip(self, ip_str: str) -> None:
        """Manually register an IP as local."""
        with self._registry_lock:
            try:
                ip_obj = ipaddress.ip_address(ip_str.strip())
                self._local_ips.add(str(ip_obj))
            except ValueError:
                pass

    def register_manual_subnet(self, cidr_str: str) -> None:
        """Manually register a CIDR subnet as local."""
        with self._registry_lock:
            try:
                net = ipaddress.ip_network(cidr_str.strip(), strict=False)
                self._local_networks.append(net)
            except ValueError:
                pass

    def get_flow_perspective(self, src_ip: str, dst_ip: str) -> EndpointRole:
        """Determines the directional perspective of a flow relative to local endpoints."""
        src_local = self.is_local_ip(src_ip)
        dst_local = self.is_local_ip(dst_ip)

        if src_local and dst_local:
            return EndpointRole.INTERNAL_LAN
        elif src_local and not dst_local:
            return EndpointRole.LOCAL_OUTBOUND
        elif not src_local and dst_local:
            return EndpointRole.LOCAL_INBOUND
        else:
            return EndpointRole.EXTERNAL_TRANSIT

    def get_summary(self) -> Dict[str, Any]:
        """Returns summary statistics about discovered local endpoints."""
        with self._registry_lock:
            return {
                "total_local_ips": len(self._local_ips),
                "local_ips": sorted(list(self._local_ips)),
                "total_subnets": len(self._local_networks),
                "subnets": [str(net) for net in self._local_networks],
                "last_refresh_epoch": self._last_refresh_time,
            }
