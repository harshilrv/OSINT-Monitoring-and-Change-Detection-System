from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict


@dataclass
class Finding:
    type: str
    value: str
    source: str
    target: str
    confidence: float = 0.5
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
