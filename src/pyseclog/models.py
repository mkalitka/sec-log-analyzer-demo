from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class Event:
    timestamp: datetime
    severity: Severity
    src_ip: str
    event_type: str
    msg: str
    raw: str


@dataclass
class Finding:
    rule: str
    timestamp_first: datetime
    timestamp_last: datetime
    src_ip: str
    summary: str
    details: Dict
    severity: Severity
