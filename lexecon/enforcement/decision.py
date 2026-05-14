"""Decision types for Lexecon enforcement."""
from dataclasses import dataclass
from enum import Enum


class DecisionType(str, Enum):
    """Possible enforcement decisions.

    ESCALATE (human-in-the-loop approval) is a planned Phase 2 feature and is
    not implemented. Do not add ESCALATE back until the escalation handler and
    its tests are in place.
    """

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class Decision:
    """An explicit enforcement decision for a proposed tool call."""

    decision: DecisionType
    reason: str
    policy_id: str | None = None

    @property
    def allowed(self) -> bool:
        """Only an explicit ALLOW decision permits execution."""
        return self.decision == DecisionType.ALLOW
