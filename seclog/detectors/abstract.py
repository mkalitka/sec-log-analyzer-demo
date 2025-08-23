from abc import ABC, abstractmethod

from ..models import Event, Finding


class AbstractDetector(ABC):
    name: str = "abstract"

    @abstractmethod
    def feed(self, e: Event) -> None:
        """Stream one event into the rule."""
        pass

    @abstractmethod
    def flush(self) -> list[Finding]:
        """Return any buffered findings at the end."""
        pass
