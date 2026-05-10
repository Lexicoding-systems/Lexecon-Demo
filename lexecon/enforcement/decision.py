"""Decision types for Lexecon enforcement."""
from dataclasses import dataclass
from enum import Enum


class DecisionType(str, Enum):
    """Possible enforcement decisions."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


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
