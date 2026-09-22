"""TraceGate checks proposed operations; it never executes them."""

from .engine import evaluate_plan
from .policy import Policy, load_policy

__all__ = ["Policy", "evaluate_plan", "load_policy"]
__version__ = "0.1.0"
