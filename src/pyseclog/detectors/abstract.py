from ..models import Event, Finding


class AbstractDetector:
    name: str = "abstract"

    def feed(self, e: Event):
        """Stream one event into the rule."""
        raise NotImplementedError

    def flush(self) -> list[Finding]:
        """Return any buffered findings at the end."""
        return []
