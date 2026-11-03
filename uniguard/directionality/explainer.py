"""Directionality Explainability and Root Cause Attribution.

Translates complex statistical asymmetry and packet dependency vectors
into clear, transparent evidence statements for SOC analysts and incident reports (Task 19).
"""

from __future__ import annotations

from typing import Dict, List, Any
from uniguard.directionality.unsupervised_model import DirectionalityResult, DirectionalityState


class DirectionalityExplainer:
    """Generates human-readable evidence summaries for flow directionality decisions."""

    @classmethod
    def explain(cls, result: DirectionalityResult) -> Dict[str, Any]:
        """Produces a structured explanation card for desktop UI and SOC logs."""
        state = result.state.value
        score = result.score
        conf = result.confidence
        feats = result.features

        fwd_pkts = int(feats.get("forward_packet_count", 0))
        rev_pkts = int(feats.get("reverse_packet_count", 0))
        fwd_bytes = int(feats.get("forward_byte_count", 0))
        rev_bytes = int(feats.get("reverse_byte_count", 0))
        ap = feats.get("packet_asymmetry", 0.0)
        ab = feats.get("byte_asymmetry", 0.0)
        burst_trans = feats.get("burst_transition_rate", 0.0)
        rev_ack = feats.get("reverse_ack_ratio", 0.0)

        evidence_bullets: List[str] = []

        # 1. Packet & Byte Imbalance
        evidence_bullets.append(f"Forward Traffic: {fwd_pkts:,} packets ({fwd_bytes:,} bytes)")
        evidence_bullets.append(f"Reverse Traffic: {rev_pkts:,} packets ({rev_bytes:,} bytes)")
        evidence_bullets.append(f"Normalized Packet Asymmetry (Ap): {ap:.3f} / 1.000")
        evidence_bullets.append(f"Normalized Byte Asymmetry (Ab): {ab:.3f} / 1.000")

        # 2. Dependency & Conversational Evidence
        if rev_pkts == 0:
            evidence_bullets.append("Reverse Activity: Completely absent (100% one-way traffic on wire)")
        elif rev_ack > 0.5:
            evidence_bullets.append(f"Reverse ACK Pacing: Active ({rev_ack * 100:.1f}% forward packets acknowledged)")
        else:
            evidence_bullets.append(f"Reverse ACK Pacing: Sparse ({rev_ack * 100:.1f}% forward packets acknowledged)")

        if burst_trans > 0.10:
            evidence_bullets.append(f"Directional Burst Transitions: Highly conversational ({burst_trans:.3f})")
        else:
            evidence_bullets.append(f"Directional Burst Transitions: Unidirectional burst ({burst_trans:.3f})")

        # 3. Decision statement
        if result.is_excluded_from_unidirectional_security:
            decision = "EXCLUDED from unidirectional threat analysis (Traffic is balanced/conversational)"
        else:
            decision = "ROUTED to unidirectional ML threat detection pipeline"

        # 4. 5/20 comparison
        b520 = result.baseline_5_20
        b_label = b520.get("baseline_5_20", {}).get("baseline_label", "N/A")
        insight = b520.get("scientific_insight", "")

        return {
            "title": "FLOW DIRECTIONALITY & ASYMMETRY ANALYSIS",
            "state": state,
            "score": round(score, 3),
            "confidence": round(conf, 3),
            "decision": decision,
            "evidence_bullets": evidence_bullets,
            "baseline_5_20_comparison": {
                "label": b_label,
                "insight": insight,
            },
        }

    @classmethod
    def format_text(cls, result: DirectionalityResult) -> str:
        """Formats the explanation as a formatted multiline string for UI text widgets."""
        expl = cls.explain(result)
        lines = [
            f"=== {expl['title']} ===",
            f"Directionality State:  {expl['state']}",
            f"Directionality Score:  {expl['score']:.3f} (0.0=Balanced, 1.0=One-Way)",
            f"Classification Conf:   {expl['confidence'] * 100:.1f}%",
            f"Pipeline Routing:      {expl['decision']}",
            "-" * 55,
            "OBSERVED BEHAVIORAL EVIDENCE:",
        ]
        for bullet in expl["evidence_bullets"]:
            lines.append(f"  * {bullet}")

        lines.append("-" * 55)
        lines.append("5/20 RESEARCH BASELINE CONTRAST:")
        lines.append(f"  * Baseline Label: {expl['baseline_5_20_comparison']['label']}")
        lines.append(f"  * Contrast Insight: {expl['baseline_5_20_comparison']['insight']}")
        return "\n".join(lines)
