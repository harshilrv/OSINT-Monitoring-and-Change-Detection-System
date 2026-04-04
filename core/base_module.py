from abc import ABC, abstractmethod
from typing import List
from core.models import Finding


class BaseModule(ABC):
    """
    Base class for all OSINT modules.
    Every module MUST inherit from this.
    """

    name: str = "base"
    supported_targets: List[str] = []

    @abstractmethod
    def run(self, target: str) -> List[Finding]:
        """
        Execute the module against a target.
        Must return a list of Finding objects.
        """
        pass
