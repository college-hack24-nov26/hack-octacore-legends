"""Consistent Flow-Hashing Affinity Dispatcher for Multi-Worker Ingestion.

Ensures that all packets of a bidirectional conversation (forward and reverse)
consistently route to the same worker thread or tracker instance to preserve
packet ordering, directional counters, TCP state, and dependency metrics (Task 18).
"""

from __future__ import annotations

import hashlib
from typing import Tuple, List, Callable, Any, Optional
from uniguard.directionality.flow_identity import CanonicalFlowKey


class FlowAffinityDispatcher:
    """Dispatches raw packets to worker partitions using consistent 5-tuple hashing."""

    def __init__(self, num_workers: int = 4) -> None:
        if num_workers < 1:
            raise ValueError(f"num_workers must be >= 1, got {num_workers}")
        self.num_workers = num_workers

    def get_worker_index(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
    ) -> int:
        """Computes deterministic worker index [0, num_workers - 1] for a packet.

        Uses the canonical 5-tuple so both A->B and B->A packets hash to the identical worker!
        """
        canonical_key = CanonicalFlowKey.from_endpoints(src_ip, dst_ip, src_port, dst_port, proto)
        # Fast 64-bit integer hash of canonical endpoints
        h = hash((
            canonical_key.endpoint_low[0],
            canonical_key.endpoint_low[1],
            canonical_key.endpoint_high[0],
            canonical_key.endpoint_high[1],
            canonical_key.proto,
        ))
        return abs(h) % self.num_workers

    def dispatch_packet(
        self,
        packet_tuple: Tuple[str, str, int, int, int, int, float, Optional[int]],
        worker_handlers: List[Callable[[Tuple[str, str, int, int, int, int, float, Optional[int]]], None]],
    ) -> int:
        """Routes the packet tuple to the affinity-assigned worker handler."""
        src_ip, dst_ip, src_port, dst_port, proto, pkt_len, ts, flags = packet_tuple
        idx = self.get_worker_index(src_ip, dst_ip, src_port, dst_port, proto)
        if idx < len(worker_handlers):
            worker_handlers[idx](packet_tuple)
        return idx
