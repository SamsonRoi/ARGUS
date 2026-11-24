
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Session:
    target_type: str | None = None
    target: list[str] | None = None
    started_at: datetime | None = None

    def set_target(self, target_type: str, target: list[str]):
        self.target_type = target_type
        self.target = target
        self.started_at = datetime.now().astimezone()

    def clear(self):
        self.target_type = None
        self.target = None
        self.started_at = None

    @property
    def is_active(self):
        return bool(self.target)
