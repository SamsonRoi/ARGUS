from dataclasses import dataclass
from datetime import datetime

from argus.modules.models import ScanResult


@dataclass
class Session:
    target_type: str | None = None
    target: list[str] | None = None
    started_at: datetime | None = None
    scan_result: ScanResult | None = None
    scan_id: int | None = None          # id of scan_result in the history
    engagement_id: int | None = None    # engagement new scans are filed under
    engagement_name: str | None = None

    def set_target(self, target_type: str, target: list[str]):
        self.target_type = target_type

        # Store a copy so later changes to the caller's list
        # cannot silently change the session.
        self.target = list(target)

        # The session starts when the first target is stored.
        # Replacing a target keeps the original start time.
        if self.started_at is None:
            self.started_at = datetime.now().astimezone()

    def clear(self):
        self.target_type = None
        self.target = None
        self.started_at = None
        self.scan_result = None
        self.scan_id = None
        self.engagement_id = None
        self.engagement_name = None

    @property
    def is_active(self):
        return bool(self.target)