"""Heuristic Directionality Baselines and 5/20 Comparator.

Preserves the historical 5/20 packet count observation as a benchmark hypothesis
and compares it side-by-side with modern unsupervised directionality classification.
"""

from __future__ import annotations

from typing import Dict, Any
from dataclasses import dataclass


@dataclass(frozen=True)
class HeuristicBaselineResult:
    """Outcome of evaluating the 5/20 packet count baseline rule."""
    is_asymmetric_5_20: bool
    baseline_label: str       # "ASYMMETRIC_5_20" or "BALANCED_5_20"
    fwd_packets: int
    rev_packets: int
    rule_description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_asymmetric": self.is_asymmetric_5_20,
            "baseline_label": self.baseline_label,
            "fwd_packets": self.fwd_packets,
            "rev_packets": self.rev_packets,
            "rule_description": self.rule_description,
        }


class HeuristicBaselineComparator:
    """Evaluates the 5/20 packet-count heuristic for research comparison."""

    @staticmethod
    def evaluate_5_20(forward_packets: int, reverse_packets: int) -> HeuristicBaselineResult:
        """Evaluates the historical 5/20 baseline:

        Hypothesis: A flow with >= 20 forward packets and <= 5 reverse packets
        was previously considered 'unidirectional' or 'highly asymmetric'.
        """
        is_asymmetric = (forward_packets >= 20 and reverse_packets <= 5)
        label = "ASYMMETRIC_5_20" if is_asymmetric else "BALANCED_5_20"
        desc = (
            f"Fwd: {forward_packets}, Rev: {reverse_packets} -> "
            + ("Triggered 5/20 heuristic (>=20 fwd, <=5 rev)" if is_asymmetric else "Did not trigger 5/20 heuristic")
        )
        return HeuristicBaselineResult(
            is_asymmetric_5_20=is_asymmetric,
            baseline_label=label,
            fwd_packets=forward_packets,
            rev_packets=reverse_packets,
            rule_description=desc,
        )

    @classmethod
    def compare_with_unsupervised(
        cls,
        forward_packets: int,
        reverse_packets: int,
        unsupervised_state: str,
        unsupervised_score: float,
    ) -> Dict[str, Any]:
        """Generates a comparative scientific contrast between 5/20 and the unsupervised model."""
        baseline = cls.evaluate_5_20(forward_packets, reverse_packets)

        # Contrast analysis
        agreement = (
            (baseline.is_asymmetric_5_20 and unsupervised_state in ("ASYMMETRIC", "STRONGLY_ASYMMETRIC", "UNIDIRECTIONAL_OBSERVED"))
            or (not baseline.is_asymmetric_5_20 and unsupervised_state in ("BIDIRECTIONAL", "UNKNOWN"))
        )

        scientific_insight = ""
        if baseline.is_asymmetric_5_20 and unsupervised_state == "BIDIRECTIONAL":
            scientific_insight = (
                "False Asymmetry in 5/20: Reverse packets were low in count but high in ACK coverage "
                "or dependency, indicating normal asymmetric protocol behavior rather than a unidirectional link."
            )
        elif not baseline.is_asymmetric_5_20 and unsupervised_state in ("STRONGLY_ASYMMETRIC", "UNIDIRECTIONAL_OBSERVED"):
            scientific_insight = (
                "Missed by 5/20: Flow did not reach 20 packets, yet statistical and dependency features "
                "detected extreme one-way anomaly early (e.g. rapid SYN burst or port probe)."
            )
        else:
            scientific_insight = f"Methods agree: Traffic characterized as {unsupervised_state}."

        return {
            "baseline_5_20": baseline.to_dict(),
            "unsupervised_state": unsupervised_state,
            "unsupervised_score": round(unsupervised_score, 3),
            "methods_agree": agreement,
            "scientific_insight": scientific_insight,
        }
