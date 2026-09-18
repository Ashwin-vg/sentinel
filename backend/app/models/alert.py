from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class SecurityAlert(BaseModel):
    alert_type: str
    severity: str
    source_ip: str
    username: Optional[str] = None
    failed_attempts: Optional[int] = None
    window_minutes: Optional[int] = None
    timestamp: Optional[datetime] = None
    status: str
